import pika
import json
import iot_logging

from threading import Thread
from datetime import datetime

import boto3
from flask import render_template
from flask_mail import Message

from iot_api import app
from iot_api import mail
from iot_api import rabbit_parameters
from iot_api.user_api.model import User, Alert, AlertType
from iot_api.user_api.models import Notification
from iot_api.user_api.models.NotificationData import NotificationData
from iot_api.user_api.models.NotificationPreferences import NotificationPreferences
from iot_api.user_api.models.NotificationDataCollectorSettings import NotificationDataCollectorSettings
from iot_api.user_api.models.NotificationAlertSettings import NotificationAlertSettings
from iot_api.user_api.models.NotificationAdditionalEmail import NotificationAdditionalEmail
from iot_api.user_api.models.NotificationAdditionalTelephoneNumber import NotificationAdditionalTelephoneNumber
#from iot_api.user_api.enums import WebUrl
from iot_api.user_api.singletonURL import singletonURL

from iot_api.user_api.websocket.notifications import emit_notification_event
from iot_api.user_api.websocket.alerts import emit_alert_event
from iot_api import config
import smtplib  
import email.utils
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

LOG = iot_logging.getLogger(__name__)

if config.SEND_SMS:
    try:
        sns = boto3.client('sns')
    except:
        LOG.error("Unable to connect with Amazon Web Services")

def subscribe_alert_consumers():
    thread = Thread(target = consumer)
    thread.setDaemon(True)
    thread.start()
    print('Subscribed to alert events')

def consumer():
    connection = None
    while(True):
        try:
            queue = 'alert_events'
            if not(connection and connection.is_open):
                LOG.debug('Creating new connection')
                connection = pika.BlockingConnection(rabbit_parameters)
            connection = pika.BlockingConnection(rabbit_parameters)
            channel = connection.channel()
            channel.queue_declare(queue=queue)
            channel.basic_consume(on_message_callback=handle_alert_events, queue=queue, auto_ack=True)
            LOG.debug(f"consuming events from queue [{queue}]")
            channel.start_consuming()
        except Exception as e:
            LOG.error(f"Error {e} on connection to queue {queue}. Reconnecting")
            continue

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
    if event_type == 'NEW':
        alert_type = AlertType.find_one(alert_type_code)
        users = User.find_all_user_by_organization_id(organization_id)
        users = list(filter(lambda x:(x.blocked==False and x.deleted==False and x.active == True),users))
        emit_alert_event({'alert_id': alert_id}, organization_id)

        for user in users:
            alert_settings = NotificationAlertSettings.find_one(user.id)
            dc_settings = NotificationDataCollectorSettings.find_one(user_id = user.id, data_collector_id = data_collector_id)
            preferences = NotificationPreferences.find_one(user.id)

            if alert_settings and getattr(alert_settings, alert_type.risk.lower()) and dc_settings and dc_settings.enabled:
                data = NotificationData.find_one(user.id)
                notification = Notification(type = 'NEW_ALERT', alert_id = alert_id, user_id=user.id, created_at = datetime.now())
                notification.save()
                if data and data.ws_sid and preferences and preferences.push:
                    emit_notification_event(notification.to_dict(), data.ws_sid)

            if preferences:
                if preferences.sms:
                    if user.phone and not user.phone in phones:
                        phones.append(user.phone)
                    additional = NotificationAdditionalTelephoneNumber.find(user_id = user.id)
                    for item in additional:
                        if item.active and not item.phone in phones:
                            phones.append(item.phone)

                if preferences.email:
                    if user.email and not user.email in emails:
                        emails.append(user.email)
                    additional = NotificationAdditionalEmail.find(user_id = user.id)
                    for item in additional:
                        if item.active and not item.email in emails:
                            emails.append(item.email)
                    

    # Send a SMS message to the specified phone number
    for phone in phones:
        if config.SEND_SMS:             
            sns.publish(
                PhoneNumber=phone,
                Message='New notification from RoLaGuard. There\'s a new alert: {alert_type}. You can check this accessing to https://rolaguard.com'.format(alert_type=alert_type.name),
            )

    if len(emails) > 0:
        with app.app_context():
            single = singletonURL()
            print('init email sending')
            msg = MIMEMultipart('alternative')
            msg['Subject'] = "New RoLaGuard Notification"
            msg['From'] = email.utils.formataddr((config.SMTP_SENDER_NAME, config.SMTP_SENDER))
            part = MIMEText(render_template(
                'notification.html', full_url=single.getParam(),alert_type=alert_type.name),'html')
            msg.attach(part)
            server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT)
            #server.set_debuglevel(1)
            server.ehlo()
            server.starttls()
            #stmplib docs recommend calling ehlo() before & after starttls()
            server.ehlo()
            server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)

            print(emails)
            for email_user in emails:
                try:
                    msg['To'] = email_user
                    server.sendmail(config.SMTP_SENDER,email_user, msg.as_string())
                except Exception as exc:
                    server.close()
                    print(exc)
            server.close()  
            print("finished email sending")

subscribe_alert_consumers()