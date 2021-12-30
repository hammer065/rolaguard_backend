from flask import request, render_template
from flask_restful import Resource
from flask_jwt_extended import get_jwt_identity, jwt_required
from flask_mail import Message
import boto3

import random
import string
import json
import iot_logging

from threading import Thread
from datetime import datetime, timedelta
from urllib.parse import quote_plus

from iot_api import bcrypt, mail, app
from iot_api.user_api.model import User, Webhook
#from iot_api.user_api.enums import WebUrl
from iot_api.user_api.models import (
    NotificationPreferences, NotificationAlertSettings,
    NotificationDataCollectorSettings, NotificationAdditionalEmail,
    NotificationAdditionalTelephoneNumber, DataCollector,
    NotificationAssetImportance
)
from iot_api.user_api.repository import NotificationPreferencesRepository
from iot_api.user_api import Error

from iot_api.user_api.schemas.notification_preferences_schema import NotificationPreferencesSchema

from iot_api import config 
import smtplib  
import email.utils
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


LOG = iot_logging.getLogger(__name__)

class NotificationPreferencesAPI(Resource):

    @jwt_required
    def get(self):
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)
        if not user: raise Error.Forbidden()

        preferences = NotificationPreferences.find_one(user.id)
        alert_settings = NotificationAlertSettings.find_one(user.id)
        asset_importance = NotificationAssetImportance.get_with(user.id)
        dc_settings = NotificationDataCollectorSettings.find(user.id)
        emails = NotificationAdditionalEmail.find(user.id)
        phones = NotificationAdditionalTelephoneNumber.find(user.id)
        webhooks = Webhook.find_all_by_user_id(user.id)

        emails = [item.to_dict() for item in emails]
        phones = [item.to_dict() for item in phones]
        webhooks = [item.to_dict() for item in webhooks]
        preferences = preferences.to_dict(phones, emails,webhooks)
        alert_settings = alert_settings.to_dict()
        dc_settings = [dc.to_dict() for dc in dc_settings]

        if not asset_importance:
            asset_importance = NotificationAssetImportance(user_id = user.id).save()

        tag_list = NotificationPreferencesRepository.get_asset_tags(user.id)

        response = {
            'destinations': preferences,
            'risks': alert_settings,
            'asset_importance': [
                {
                    'name': 'high',
                    'enabled': asset_importance.high,
                },
                {
                    'name': 'medium',
                    'enabled': asset_importance.medium,
                },
                {
                    'name': 'low',
                    'enabled': asset_importance.low,
                },
            ],
            'dataCollectors': dc_settings,
            'asset_tags': [{
                "id" : tag.id,
                "name" : tag.name,
                "color": tag.color
            } for tag in tag_list]
        }
        return response, 200

    @jwt_required
    def put(self):
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)
        if not user: raise Error.Forbidden()

        body = json.loads(request.data)
        parsed_result = NotificationPreferencesSchema().load(body).data
        
        global activation_emails, activation_sms
        activation_emails = []
        activation_sms = []

        # Update destinations
        try:
            destinations = parsed_result.get('destinations')
            np = NotificationPreferences.find_one(user.id)
            for destination in destinations:
                attr = destination.get('destination')
                if attr not in ('sms', 'push', 'email','webhook'):
                    LOG.error('Destination must be one these: sms, push, email, webhook. It\'s: {0}'.format(attr))
                    return {'error': 'Destination must be one these: sms, push, email, webhook'}, 400
                setattr(np, attr, destination.get('enabled'))
                if attr == 'sms' and destination.get('enabled'):
                    existing_phones = NotificationAdditionalTelephoneNumber.find(user.id)
                    for phone in existing_phones:
                        if len(list(filter(lambda item: item.get('id') == phone.id, destination.get('additional')))) == 0:
                            phone.delete()

                    for phone in destination.get('additional'):
                        id = phone.get('id')
                        phone = phone.get('phone')
                        if id:
                            filtered_phones = list(filter(lambda item: id == item.id, existing_phones))
                            if len(filtered_phones) == 0:
                                NotificationPreferences.rollback()
                                LOG.error('Not exist phone id {0}'.format(id))
                                return {'error': 'not exist id'}, 400
                            elif filtered_phones[0].phone != phone:
                                filtered_phones[0].phone = phone
                                filtered_phones[0].active = False
                                token = random_string(10)
                                filtered_phones[0].token = quote_plus(token)
                                filtered_phones[0].creation_date = datetime.now()
                                activation_sms.append({'phone': phone, 'token': filtered_phones[0].token})

                        else:
                            token = random_string(10)
                            token = quote_plus(token)
                            activation_sms.append({'phone': phone, 'token': token})
                            NotificationAdditionalTelephoneNumber(phone=phone, creation_date=datetime.now(), token = token, active = False, user_id = user.id).save() # Then change it to False

                if attr == 'email' and destination.get('enabled'):
                    existing_emails = NotificationAdditionalEmail.find(user.id)
                    for email in existing_emails:
                        if len(list(filter(lambda item: item.get('id') == email.id, destination.get('additional')))) == 0:
                            email.delete()

                    for email in destination.get('additional'):
                        id = email.get('id')
                        email = email.get('email').lower()
                        if id:
                            filtered_emails = list(filter(lambda item: id == item.id, existing_emails))
                            if len(filtered_emails) == 0:
                                NotificationPreferences.rollback()
                                LOG.error('Not exist email id {0}'.format(id))
                                return {'error': 'not exist id'}, 400
                            elif filtered_emails[0].email != email:
                                filtered_emails[0].email = email
                                filtered_emails[0].active = False
                                token = random_string(10)
                                filtered_emails[0].token = quote_plus(token)
                                filtered_emails[0].creation_date = datetime.now()
                                activation_emails.append({'email': email, 'token': filtered_emails[0].token})

                        else:
                            token = random_string(10)
                            token = quote_plus(token)
                            activation_emails.append({'email': email, 'token': token})
                            NotificationAdditionalEmail(email=email, creation_date=datetime.now(), token = token, active = False, user_id = user.id).save()

                if attr == 'webhook' and destination.get('enabled'):
                    existing_webhooks = Webhook.find_all_by_user_id(user.id)
                    for webhook in existing_webhooks:
                        if len(list(filter(lambda item: item.get('id') == webhook.id, destination.get('additional')))) == 0:
                            webhook.delete()

                    for webhook in destination.get('additional'):
                        if webhook and not webhook.get('id'):
                            Webhook(webhook_user_id=user.id,target_url=webhook.get('url'),url_secret=webhook.get('secret'),active=True).save()

            # Update emails -> Delete removed, add new as pending, change to pending to updated
            # Update phones ->Delete removed, add new as pending, change to pending to updated

            # Update risks
            risks = parsed_result.get('risks')
            nas = NotificationAlertSettings.find_one(user.id)  
            for risk in risks:
                attr = risk.get('name')
                if attr not in ('high', 'medium', 'low', 'info'):
                    NotificationPreferences.rollback()
                    LOG.error('Risk must be one these: high, medium, low, info. But it\'s: {0}'.format(attr))
                    return {'error': 'Risk must be one these: high, medium, low, info'}, 400
                setattr(nas, attr, risk.get('enabled'))

            # Update asset importances
            asset_importances = parsed_result.get('asset_importance')
            nai = NotificationAssetImportance.get_with(user_id = user.id)
            for importance in asset_importances:
                attr = importance.get('name')
                if attr not in ('high', 'medium', 'low'):
                    raise Error.BadRequest('Asset importance name must be one these: high, medium, low. But it\'s: {0}'.format(attr))
                setattr(nai, attr, importance.get('enabled'))

            # Update asset tags
            asset_tags = parsed_result.get('asset_tags')
            tag_id_list = [tag.get('id') for tag in asset_tags]
            NotificationPreferencesRepository.set_asset_tags(user.id, tag_id_list, False)

            # Update data collectors. Check if dc belongs to user organization
            data_collectors = parsed_result.get('data_collectors')
            for dcp in data_collectors:
                dc = DataCollector.find_by_id(dcp.get('data_collector_id'))
                if dc and dc.organization_id != user.organization_id:
                    NotificationPreferences.rollback()
                    return None, 403
                if dc:
                    settings = NotificationDataCollectorSettings.find_one(user_id = user.id, data_collector_id = dc.id)
                if dc and settings:
                    settings.enabled = dcp.get('enabled')

            NotificationPreferences.commit()
            
            thread = Thread(target = send_activation_emails)
            thread.setDaemon(True)
            thread.start()

            thread = Thread(target = send_activation_sms)
            thread.setDaemon(True)
            thread.start()

        except Exception as exc:
            NotificationPreferences.rollback()
            LOG.error(exc)
            return {'error': 'Something went wrong'}, 500


class NotificationEmailActivationAPI(Resource):

    def put(self, token):
        email = NotificationAdditionalEmail.find_one_by_token(token)

        if not email:
            return None, 404
        
        if email.active:
            return {'code': 'EMAIL_ALREADY_ACTIVE'}, 400

        if email.creation_date + timedelta(hours=24) < datetime.now():
            return {'code': 'DISABLED_TOKEN'}

        email.active = True
        email.update()
        return {'email': email.email}, 200


class NotificationPhoneActivationAPI(Resource):

    def put(self, token):
        phone = NotificationAdditionalTelephoneNumber.find_one_by_token(token)

        if not phone:
            return None, 404
        
        if phone.active:
            return {'code': 'PHONE_ALREADY_ACTIVE'}, 400

        if phone.creation_date + timedelta(hours=24) < datetime.now():
            return {'code': 'DISABLED_TOKEN'}

        phone.active = True
        phone.update()
        return {'phone': phone.phone}, 200        

def send_activation_emails():
    if config.SEND_EMAILS:
        with app.app_context():
            server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT)
            #server.set_debuglevel(1)
            server.ehlo()
            server.starttls()
            #stmplib docs recommend calling ehlo() before & after starttls()
            server.ehlo()
            server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"{config.BRAND_NAME} Email Confirmation"
            msg['From'] = email.utils.formataddr((config.SMTP_SENDER_NAME, config.SMTP_SENDER))

            for item in activation_emails:
                token = item.get('token')
                email_user = item.get('email')
                full_url = config.BRAND_URL + "notifications/email_activation/" + str(token)
                print('init email sending')
                msg['To'] = email_user
                part = MIMEText(render_template(
                    'notification_activation.html',
                    brand_name=config.BRAND_NAME,
                    full_url=full_url
                    ),'html')
                msg.attach(part)
                server.sendmail(config.SMTP_SENDER,email_user, msg.as_string())
                print("finished email sending")
            server.close()    

def send_activation_sms():
    if config.SEND_SMS:
        sns = boto3.client('sns')
        for item in activation_sms:
            token = item.get('token')
            phone = item.get('phone')
            full_url = config.BRAND_URL + "notifications/phone_activation/" + str(token)
            sns.publish(
                PhoneNumber=phone,
                Message=f'Please activate this phone to receive {config.BRAND_NAME} notifications by clicking the link ' + full_url,
            )

def random_string(length):
    """Generate a random string with the combination of lowercase and uppercase letters """
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(length))