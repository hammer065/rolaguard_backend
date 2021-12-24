import pika
import json
import iot_logging

from threading import Thread
from datetime import datetime

import boto3

from iot_api import app
from iot_api import rabbit_parameters
from iot_api.user_api.model import User, Alert, AlertType, Webhook
from iot_api.user_api.models import (
    NotificationPreferences, NotificationDataCollectorSettings,
    NotificationAlertSettings, NotificationAssetImportance, NotificationAdditionalEmail,
    NotificationAdditionalTelephoneNumber, NotificationAssetTag
)
from iot_api.user_api.repository import AssetRepository, DeviceRepository, GatewayRepository
#from iot_api.user_api.enums import WebUrl

from iot_api.user_api.websocket.alerts import emit_alert_event
from iot_api import config

LOG = iot_logging.getLogger(__name__)

sns=None
if config.SEND_SMS:
    try:
        sns = boto3.client('sns')
    except:
        LOG.error("Unable to connect with Amazon Web Services")

def subscribe_alert_consumers():
    thread = Thread(target = consumer)
    thread.setDaemon(True)
    thread.start()

def consumer():
    queue="alert_events"
    while(True):
        try:
            LOG.debug('Creating new connection to queue alert_events')
            connection = pika.BlockingConnection(rabbit_parameters)
            channel = connection.channel()
            channel.queue_declare(queue=queue)
            channel.basic_consume(on_message_callback=handle_alert_events, queue=queue, auto_ack=True)
            channel.start_consuming()
        except Exception as e:
            LOG.error(f"Error on connection to queue alert_events. Retrying connection.")

def handle_alert_events(ch, method, properties, body):
    event = None
    try:
        event = json.loads(body)        
    except Exception:
        LOG.error("Couldn't deserialize event")

    if not event:
        return 
    alert_id = event.get('alert_id')
    organization_id = event.get('organization_id')
    data_collector_id = event.get('data_collector_id')
    event_type = event.get('event_type')
    alert_type_code = event.get('alert_type')
    phones = []
    emails = []
    webhooks = {}
    if event_type == 'NEW':
        alert_type = AlertType.find_one(alert_type_code)
        users = User.find_all_user_by_organization_id(organization_id)
        users = list(filter(lambda x:(x.blocked==False and x.deleted==False and x.active == True),users))
        emit_alert_event({'alert_id': alert_id}, organization_id)

        try:
            alert = Alert.find_one(alert_id)
            device = None
            gateway = None
            if alert and alert.device_id:
                device = AssetRepository.get_with(alert.device_id, "device")
            if alert and alert.gateway_id:
                gateway = AssetRepository.get_with(alert.gateway_id, "gateway")
        except Exception as e:
            LOG.error(f"Error {e} on alert assets search {alert}. Ignoring device/gateway related preferences")
            device = None
            gateway = None

        for user in users:
            alert_settings = NotificationAlertSettings.find_one(user.id)
            dc_settings = NotificationDataCollectorSettings.find_one(user_id = user.id, data_collector_id = data_collector_id)
            preferences = NotificationPreferences.find_one(user.id)

            # Check whether the alert assets are important for the user or not
            try:
                asset_importance = NotificationAssetImportance.get_with(user.id)
                is_important_for_user = False
                if asset_importance and device is not None:
                    is_important_for_user = getattr(asset_importance, device.importance.value.lower())
                elif asset_importance:
                    is_important_for_user = getattr(asset_importance, gateway.importance.value.lower())
            except Exception as e:
                LOG.error(f"Error {e} on NotificationAssetImportance search for user {user.id}. Ignoring asset_importance preference")
                is_important_for_user = True

            # Check whether the alert assets contain all the tags in user notification preferences or not
            try:
                asset_tags = NotificationAssetTag.find_all_with(user_id = user.id)
                tag_id_list = [asset_tag.tag_id for asset_tag in asset_tags]
                if device:
                    has_all_tags = DeviceRepository.has_all_tags(device.id, tag_id_list)
                elif gateway:
                    has_all_tags = GatewayRepository.has_all_tags(gateway.id, tag_id_list)
            except Exception as e:
                LOG.error(f"Error {e} on handling NotificationAssetTag preferences for user {user.id}. Ignoring this preference")
                has_all_tags = True

            if not(alert_settings 
            and alert_type 
            and getattr(alert_settings, alert_type.risk.lower())
            and is_important_for_user
            and has_all_tags
            and dc_settings
            and dc_settings.enabled):
                continue

            if preferences:
                if preferences.sms:
                    NotificationAdditionalTelephoneNumber.add_not_repeated(user,phones)

                if preferences.email:
                    NotificationAdditionalEmail.add_not_repeated(user,emails)
                
                if preferences.webhook:
                    Webhook.add_not_repeated(user,webhooks)

    # Send a SMS message to the specified phone number
    if sns:
        NotificationAdditionalTelephoneNumber.send_sms(sns,alert_type,phones)
    
    NotificationAdditionalEmail.send_emails(app,alert_type,emails)
    
    # Send a POST request to the specified url
    # If the destination supports authentication, it will send a signature within the request
    Webhook.send_request(alert,webhooks)

subscribe_alert_consumers()