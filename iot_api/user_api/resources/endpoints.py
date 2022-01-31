import datetime
import email.utils
import hashlib
import json
import os
import re
import smtplib
from iot_api.user_api.models.DataCollectorGateway import DataCollectorGateway
import socket
import uuid
import validators
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import dateutil.parser as dp
import requests
from flask import jsonify, make_response, request, render_template, session
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_optional, jwt_required, get_jwt_identity,
                                get_raw_jwt,
                                jwt_refresh_token_required)

from flask_restful import Resource, reqparse
from validate_email import validate_email

import iot_logging

from iot_api import cipher_suite
from iot_api import config
from iot_api.user_api import Error
from iot_api.user_api.enums import RoleTypes
from iot_api.user_api.events.data_collector_events import emit_data_collector_event
from iot_api.user_api.events.policy_events import emit_policy_event
from iot_api.user_api.model import User, Organization, Device, AccountActivation, \
    UserRole, UserToUserRole, Alert, AlertType, Packet, \
    get_user_collector_ids
from iot_api.user_api.models import ChangeEmailRequests, GlobalData, LoginAttempts, PasswordReset, \
    RevokedTokenModel, SendMailAttempts, StatsCounters
from iot_api.user_api.models.DataCollector import DataCollector, DataCollectorStatus
from iot_api.user_api.models.DataCollectorLogEvent import DataCollectorLogEvent, DataCollectorLogEventType
from iot_api.user_api.models.DataCollectorType import DataCollectorType
from iot_api.user_api.models.TTNRegion import TTNRegion
from iot_api.user_api.models.MqttTopic import MqttTopic
from iot_api.user_api.models.NotificationAlertSettings import NotificationAlertSettings
from iot_api.user_api.models.NotificationData import NotificationData
from iot_api.user_api.models.NotificationDataCollectorSettings import NotificationDataCollectorSettings
from iot_api.user_api.models.NotificationPreferences import NotificationPreferences
from iot_api.user_api.models.Policy import Policy
from iot_api.user_api.model import Quarantine

from urllib.parse import urlencode
from urllib.request import urlopen
import json

import phonenumbers

TTN_COLLECTOR = 'ttn_collector'
TTN_V3_COLLECTOR = 'ttn_v3_collector'

LOG = iot_logging.getLogger(__name__)

USE_RECAPTCHA = ("RECAPTCHA_SECRET_KEY" in os.environ) and (len(os.environ['RECAPTCHA_SECRET_KEY']) > 0)

def empty_string_none(value):
    return value != "" and value or None

data_collector_parser = reqparse.RequestParser()
data_collector_parser.add_argument("name", help="Missing name attribute", required=True)
data_collector_parser.add_argument("description", help="Missing description attribute", required=False)
data_collector_parser.add_argument("ip", help="Missing ip attribute", required=False)
data_collector_parser.add_argument("port", help="Missing port attribute", required=False)
data_collector_parser.add_argument("user", help="Missing user attribute", required=False)
data_collector_parser.add_argument("password", help="Missing password attribute", required=False)
data_collector_parser.add_argument("ssl", help="Missing ssl attribute", required=False)
data_collector_parser.add_argument("ca_cert", help="Missing ca_cert attribute", required=False, type=empty_string_none)
data_collector_parser.add_argument("client_cert", help="Missing cient_cert attribute", required=False, type=empty_string_none)
data_collector_parser.add_argument("client_key", help="Missing client_key attribute", required=False, type=empty_string_none)
data_collector_parser.add_argument("data_collector_type_id", help="Missing type attribute", required=True)
data_collector_parser.add_argument("policy_id", help="Missing policy attribute", required=True)
data_collector_parser.add_argument("gateway_id", help="Missing gateway_id attribute", required=False)
data_collector_parser.add_argument("gateway_name", help="Missing gateway_name attribute", required=False)
data_collector_parser.add_argument("gateway_api_key", help="Missing gateway_api_key attribute", required=False)
data_collector_parser.add_argument("region_id", help="Missing region_id attribute", required=False)
data_collector_parser.add_argument("topics", help="Missing topics attribute", required=False, action="append")
data_collector_parser.add_argument("custom_ip", required=False)

register_parser = reqparse.RequestParser()
register_parser.add_argument("username", help="Missing username attribute.", required=True)
register_parser.add_argument("full_name", help="Missing full_name attribute.", required=True)
register_parser.add_argument("email", help="Missing email attribute.", required=True)
register_parser.add_argument("phone", help="Missing phone attribute.", required=False)
register_parser.add_argument("user_roles", help="Missing user_roles attribute.", required=False)
register_parser.add_argument("data_collectors", help="Missing data_collectors attribute.", required=False,
                             action="append")
register_parser.add_argument("recaptcha_token", help="Missing recaptcha_token attribute.", required=False)

login_parser = reqparse.RequestParser()
login_parser.add_argument("username", dest="username_or_email", help="You have to enter username or email",
                          required=True)
login_parser.add_argument("password", help="You have to enter a password", required=True)

register_organization_parser = reqparse.RequestParser()
register_organization_parser.add_argument("name", help="Missing organization name attribute.", required=True)
register_organization_parser.add_argument("country", help="Missing country attribute.", required=True)
register_organization_parser.add_argument("region", help="Missing region attribute.", required=True)

update_organization_parser = reqparse.RequestParser()
update_organization_parser.add_argument("country", help="Missing country attribute.", required=True)
update_organization_parser.add_argument("region", help="Missing region attribute.", required=True)

# User
user_update_parser = reqparse.RequestParser()
user_update_parser.add_argument("full_name", help="Missing full_name attribute.", required=True)
user_update_parser.add_argument("phone", help="Missing phone attribute.", required=False)
user_update_parser.add_argument("user_roles", help="Missing user_roles attribute.", required=True, action="append")
user_update_parser.add_argument("data_collectors", help="Missing data_collectors attribute.", required=False,
                                action="append")
user_update_parser.add_argument("first_login", help="Missing first_login attribute.", required=False)

user_change_password_parser = reqparse.RequestParser()
user_change_password_parser.add_argument("password", help="Missing password attribute.", required=True)
user_change_password_parser.add_argument("current_password", help="Missing current password attribute.", required=True)

user_change_email_parser = reqparse.RequestParser()
user_change_email_parser.add_argument("current_password", help="Missing current password attribute.", required=True)
user_change_email_parser.add_argument("email", help="Missing email attribute.", required=True)

user_create_password_parser = reqparse.RequestParser()
user_create_password_parser.add_argument("password", help="Missing password attribute.", required=True)

user_resend_activation_parser = reqparse.RequestParser()
user_resend_activation_parser.add_argument("email", help="Missing email attribute.", required=True)

user_recover_password_parser = reqparse.RequestParser()
user_recover_password_parser.add_argument("email", dest="username_or_email", help="Missing email or username attribute.", required=True)
user_recover_password_parser.add_argument("recaptcha_token", help="Missing recaptcha_token attribute.", required=USE_RECAPTCHA)

user_change_password_by_recovery_parser = reqparse.RequestParser()
user_change_password_by_recovery_parser.add_argument("password", help="Missing password attribute.", required=True)

add_recipient_parser = reqparse.RequestParser()
add_recipient_parser.add_argument("name", help="Missing name attribute.", required=True)

ttn_credentials_parser = reqparse.RequestParser()
ttn_credentials_parser.add_argument("user", dest="username", help="You have to enter username",
                          required=True)
ttn_credentials_parser.add_argument("password", help="You have to enter a password", required=True)


# verify if specified username belongs to user with role 'Regular_User'
def is_regular_user(user_id):
    role = UserRole.find_by_role_name(RoleTypes.Regular_User.value)

    if not role:
        return None
    role_id = role.id

    if not role_id:
        return None

    if UserToUserRole.find_by_user_id_and_user_role_id(user_id, role_id):
        return True
    else:
        return False


# verify if specified username belongs to user with role 'User_Admin'
def is_admin_user(user_id):
    role = UserRole.find_by_role_name(RoleTypes.User_Admin.value)

    if not role:
        return None
    role_id = role.id

    if not role_id:
        return None

    if UserToUserRole.find_by_user_id_and_user_role_id(user_id, role_id):
        return True
    else:
        return False


# verify if specified username is system
def is_system(user_id):
    role = UserRole.find_by_role_name(RoleTypes.System.value)

    if not role:
        return None
    role_id = role.id

    if not role_id:
        return None

    if not role_id:
        return None

    if UserToUserRole.find_by_user_id_and_user_role_id(user_id, role_id):
        return True
    else:
        return False


def validate_password(password):
    length_error = len(password) < 8 or len(password) > 50
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[ !#$%&'()*+,-./:;<=>?@[\\\]^_`{|}~" + r'"]', password) is None

    return length_error or digit_error or uppercase_error or lowercase_error or symbol_error


def forbidden():
    return make_response(jsonify({"error": "forbidden access"}), 403)


def unauthorized():
    return make_response(jsonify({"error": "Failed login."}), 401)


def internal(msg):
    return make_response(jsonify({"error": msg}), 500)


def bad_request(msg):
    return make_response(jsonify({"error": msg}), 400)


def not_found():
    return make_response(jsonify({"error": "not found"}), 404)

class UserInfoAPI(Resource):

    @jwt_required
    def get(self, username):

        user = User.find_by_username(get_jwt_identity())

        if not user:
            return forbidden()

        current_user = User.find_by_username(username)

        if is_system(current_user.id):
            return forbidden()

        if not current_user:
            return internal("User {0} could not be found.".format(username.lower()))

        # restrict access to user admin, super admin and profile owner

        if not is_admin_user(user.id):
            if current_user.username != user.username:
                return forbidden()

        if user.organization_id != current_user.organization_id:
            return forbidden()

        return current_user.to_json()

    @jwt_required
    def put(self, username):
        user = User.find_by_username(get_jwt_identity())

        if not user:
            return forbidden()

        current_user = User.find_by_username(username)

        if not current_user:
            return internal("User {0} could not be found.".format(username.lower()))

        # restrict user update to user admin, super admin and profile owner

        if not is_admin_user(user.id) and current_user.username != user.username:
                return forbidden()

        if not user.active:
            return forbidden()

        if user.organization_id != current_user.organization_id:
            return forbidden()

        data = user_update_parser.parse_args()

        # validating a phone number
    
        if data["phone"]:
            phone_number = phonenumbers.parse(data["phone"]) 
            valid = phonenumbers.is_valid_number(phone_number)
        
        if not valid:
            return internal("Phone {0} is not valid".format(phonenumbers.format_number(phone_number, phonenumbers.PhoneNumberFormat.E164)))

        user_roles = data["user_roles"]

        # updating user roles only allowed to admin user.

        if user_roles and not is_admin_user(user.id):
            return forbidden()

        user_roles_int = list(map(lambda x: int(x), user_roles))  # roles to be added

        if RoleTypes.System.value in user_roles_int:
            LOG.error("Can not include one of the roles")

            return forbidden()

        try:

            current_user_roles = UserToUserRole.find_all_user_role_by_user_id(current_user.id)
            current_user_roles_id = list(map(lambda x: x.user_role_id, current_user_roles))
            account_activation_list = AccountActivation.find_active_tokens_by_user_id(current_user.id)

            if account_activation_list:
                account_activation = account_activation_list[0]
            elif not current_user.active:  # trying to modify not active user with expired token
                # todo: resend activation mail and allow the admin to modify current user

                return forbidden()

            if not current_user_roles:
                # get current roles of not active user created after delay, with not expired token
                current_user_roles = list(account_activation.user_roles_id)
                current_user_roles = list(filter(lambda x: x != ',', current_user_roles))
                current_user_roles = [int(x) for x in current_user_roles]

            # delete obsolete roles

            for current_user_role in current_user_roles:
                # current_user_role can be a UserToUserRole object or an int list

                if isinstance(current_user_role, UserToUserRole):
                    user_role_id = current_user_role.user_role_id
                else:
                    user_role_id = current_user_role
                    current_user_roles_id.append(user_role_id)

                if current_user.id == user.id and 1 in user_roles_int and user_role_id == 2:  # cant auto-downgrade role
                    return forbidden()

                if user_role_id not in user_roles_int:
                    if current_user.active or isinstance(current_user_role, UserToUserRole):
                        # deleting obsolete role from active user or not active created before delay
                        try:
                            current_user_role.delete_from_db()
                        except Exception as exc:
                            current_user_role.rollback()
                            raise exc                 

            # add new added roles to user

            for role_to_add in user_roles_int:
                if role_to_add not in current_user_roles_id:
                    if UserRole.find_by_id(role_to_add):
                        if current_user.active or isinstance(current_user_role, UserToUserRole):
                            # adding role to active user or not active user created before delay
                            new_user_to_user_role = UserToUserRole(
                                user_id=current_user.id,
                                user_role_id=role_to_add
                            )
                            try:
                                new_user_to_user_role.save_to_db()
                            except Exception as exc:
                                new_user_to_user_role.rollback()
                                raise exc                                
                        elif account_activation:  # adding role to not active user created after delay
                            account_activation.user_roles_id = role_to_add
                            try:
                                account_activation.update_to_db()
                            except Exception as exc:
                                account_activation.rollback()
                                raise exc  
                    else:
                        LOG.error(f"Error creating User to User Role relation: User Role with id ({role_to_add}) does not exist!")

            if "data_collectors" in data and data["data_collectors"] is not None and len(data["data_collectors"]) > 0:
                collector_id_strings = data["data_collectors"]
                collector_ids = list(map(lambda x: int(x), collector_id_strings))
                collectors = DataCollector.find_with( collector_ids, user.organization_id)
            else:
                collectors = []

            # cast first_login value
            if data["first_login"]:
                if data["first_login"] == 'False':
                    current_user.first_login = False
                else:
                    current_user.first_login  = True

            # update data in current user after checking that it has an active token or it's an active user,
            # and that it's not trying to autodowngrade role
            current_user.full_name = data["full_name"]
            current_user.phone = phonenumbers.format_number(phone_number, phonenumbers.PhoneNumberFormat.E164)
            current_user.collectors = collectors
            try:
                current_user.update_to_db()
            except Exception as exc:
                current_user.rollback()
                raise exc  

            #return updated user
            return jsonify(current_user.to_json())
        except Exception as exc:
            LOG.error("Something went wrong trying to update the User {0}: {1}".format(current_user.username, exc))

            return internal("Something went wrong trying to update the User {0}.".format(current_user.username))

    @jwt_required
    def delete(self, username):
        # WIP: deassociate rows in several tables when user is deleted
        user = User.find_by_username(get_jwt_identity())

        if not user:
            return forbidden()

        # restrict user deletion to user admin and super admin

        if not is_admin_user(user.id):
            return forbidden()

        current_user = User.find_by_username(username)

        # block user from deleting its own account

        if current_user.username == user.username:
            return forbidden()

        # Make sure it's trying to delete a user of its organization

        if user.organization_id != current_user.organization_id:
            return forbidden()

        if not current_user:
            return internal("User {0} could not be found.".format(username.lower()))

        try:
            current_user.deleted = True
            current_user.update_to_db()

            return jsonify({"message": "User {0} was deleted successfully.".format(username.lower())})

        except Exception as exc:
            current_user.rollback()
            LOG.error("Error trying to delete User: {0}".format(exc))

            return internal("Something went wrong")


class ResendActivationAPI(Resource):

    @jwt_required
    def put(self):
        user = User.find_by_username(get_jwt_identity())

        if not user:
            return forbidden()
        data = user_resend_activation_parser.parse_args()
        user_list = User.find_by_email(data["email"])

        if not is_admin_user(user.id):
            return forbidden()

        if user_list:
            new_user = user_list[0]

        try:
            user_roles_id = None
            account_activation_list = AccountActivation.find_last_tokens_by_user_id(new_user.id)

            for account_activation in account_activation_list:
                if account_activation.active:
                    account_activation.active = False
                    try:
                        account_activation.update_to_db()
                    except Exception as exc:
                        account_activation.rollback()
                        raise exc  

            if account_activation_list:
                user_roles_id = account_activation_list[0].user_roles_id

            token = hashlib.sha256((new_user.email + str(datetime.datetime.now())).encode())
            encoded_token = token.hexdigest()

            new_account_activation = AccountActivation(
                user_id=User.find_by_username(new_user.username).id,
                token=encoded_token,
                creation_date=datetime.datetime.now().isoformat(),
                active=True,
                user_roles_id=user_roles_id
            )

            full_url = config.BRAND_URL + \
                       "activation/" + str(encoded_token)

            if config.SMTP_HOST and config.SEND_EMAILS:
                LOG.debug('init email sending')
                msg = MIMEMultipart('alternative')
                msg['Subject'] = f"{config.BRAND_NAME} Account Confirmation"
                msg['From'] = email.utils.formataddr((config.SMTP_SENDER_NAME, config.SMTP_SENDER))
                msg['To'] = new_user.email
                part = MIMEText(render_template(
                    'activation.html',
                    brand_name=config.BRAND_NAME,
                    full_url=full_url
                    ), 'html')
                msg.attach(part)
                server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT)
                # server.set_debuglevel(1)
                server.ehlo()
                server.starttls()
                # stmplib docs recommend calling ehlo() before & after starttls()
                server.ehlo()
                server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
                server.sendmail(config.SMTP_SENDER, new_user.email, msg.as_string())
                server.close()
                LOG.debug("finished email sending")
                try:
                    new_account_activation.save_to_db()
                except Exception as exc:
                    new_account_activation.rollback()
                    raise exc
                return jsonify({"message": "Activation E-mail Resent Successfully"})
            elif config.SEND_EMAILS:
                LOG.error("Mail not sent since there is not SMTP server configured.")

                return internal("Something went wrong trying to resend activation")

        except Exception as exc:
            LOG.error("Something went wrong trying to resend activation: {0}".format(exc))

            return internal("Something went wrong trying to resend activation")


class UserListAPI(Resource):

    @jwt_required
    def get(self):
        user = User.find_by_username(get_jwt_identity())
        page = request.args.get('page', default=1, type=int)
        size = request.args.get('size', default=20, type=int)

        if not user:
            return forbidden()

        # for users other than user admin, super admin and alarm admin return only user's own info to maintain privacy

        if not is_admin_user(user.id):
            return {"users": [user.to_json()]}
        else:
            try:
                result = User.find(user.organization_id, page, size)
                users = [user.to_json() for user in result.items]
                headers = {'total-pages': result.pages, 'total-items': result.total}

                return {"users": users}, 200, headers
            except Exception as exc:
                LOG.error("Something went wrong to get the list of users {0}.".format(exc))

                return internal("Something went wrong to get the list of users")


class UserAPI(Resource):

    @jwt_required
    def get(self):
        user = User.find_by_username(get_jwt_identity())

        if not user:
            return forbidden()

        return user.to_json()


class CreatePasswordAPI(Resource):

    def put(self, token):
        data = user_create_password_parser.parse_args()
        account_activation = AccountActivation.find_by_token(token)

        if not account_activation:
            return internal("Invalid token")

        try:
            current_user = User.find_by_id(account_activation.user_id)

            # token date validation
            token_time_valid = account_activation.creation_date > datetime.datetime.now(
                datetime.timezone.utc) - datetime.timedelta(hours=24)

            if not token_time_valid and not current_user.active:
                # If the token has expired, resend the activation mail with a new token

                token = hashlib.sha256((current_user.email + str(datetime.datetime.now())).encode())
                encoded_token = token.hexdigest()

                account_activation.active=False
                try:
                    account_activation.update_to_db()
                except Exception as exc:
                    account_activation.rollback()
                    raise exc  

                new_account_activation = AccountActivation(
                    user_id=User.find_by_username(current_user.username).id,
                    token=encoded_token,
                    creation_date=datetime.datetime.now().isoformat(),
                    active=True,
                    user_roles_id=account_activation.user_roles_id
                )
                try:
                    new_account_activation.save_to_db()
                except Exception as exc:
                    new_account_activation.rollback()
                    raise exc

                full_url = config.BRAND_URL + "activation/" + str(encoded_token)

                if config.SMTP_HOST and config.SEND_EMAILS:
                    LOG.debug('init email sending')
                    msg = MIMEMultipart('alternative')
                    msg['Subject'] = f"{config.BRAND_NAME} Account Confirmation"
                    msg['From'] = email.utils.formataddr((config.SMTP_SENDER_NAME, config.SMTP_SENDER))
                    msg['To'] = current_user.email
                    part = MIMEText(render_template(
                        'activation.html',
                        brand_name=config.BRAND_NAME,
                        full_url=full_url
                        ), 'html')
                    msg.attach(part)
                    server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT)
                    server.ehlo()
                    server.starttls()
                    # stmplib docs recommend calling ehlo() before & after starttls()
                    server.ehlo()
                    server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
                    server.sendmail(config.SMTP_SENDER, current_user.email, msg.as_string())
                    server.close()
                    LOG.debug("finished email sending")

                    return internal("Token expired. An email was re-sent to your account.")

                else:
                    LOG.error("Activation mail not re-sent because there is not SMTP server configured.")

                    return internal("Something went wrong trying to re-send activation mail")

            # password validation
            password_failed = validate_password(data["password"])

            if password_failed:
                return internal("Password is not valid")

            current_user.password = User.generate_hash(data["password"])
            current_user.active = True
            try:
                current_user.update_to_db()
            except Exception as exc:
                current_user.rollback()
                raise exc  

            # Deactivate active tokens
            account_activation_list = AccountActivation.find_active_tokens_by_user_id(account_activation.user_id)

            for account_activation in account_activation_list:
                account_activation.active = False
                try:
                    account_activation.update_to_db()
                except Exception as exc:
                    account_activation.rollback()
                    raise exc  

            # create organization
            organization_id = current_user.organization_id

            if organization_id is None:
                # print("creating organization")
                username_without_space = current_user.username.strip()
                new_organization = Organization(
                    name=username_without_space
                )
                try:
                    new_organization.save_to_db()
                except Exception as exc:
                    new_organization.rollback()
                    raise exc
                organization_id = new_organization.id
                current_user.organization_id = organization_id
                try:
                    current_user.update_to_db()
                except Exception as exc:
                    current_user.rollback()
                    raise exc 

                info_email = os.environ['INFO_EMAIL'] if 'INFO_EMAIL' in os.environ else None

                if info_email:
                    msg = MIMEMultipart('alternative')
                    msg['Subject'] = "New Organization"
                    msg['From'] = email.utils.formataddr((config.SMTP_SENDER_NAME, config.SMTP_SENDER))
                    msg['To'] = info_email
                    part = MIMEText(render_template(
                        'new_organization.html',
                        brand_name=config.BRAND_NAME,
                        username=current_user.username,
                        fullname=current_user.full_name,
                        email=current_user.email,
                        phone=current_user.phone
                        ), 'html')
                    msg.attach(part)
                    server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT)
                    server.ehlo()
                    server.starttls()
                    # stmplib docs recommend calling ehlo() before & after starttls()
                    server.ehlo()
                    server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
                    server.sendmail(config.SMTP_SENDER, info_email, msg.as_string())
                    server.close()
            # create user role
            user_roles = None

            if account_activation.user_roles_id:
                user_roles = list(account_activation.user_roles_id)
                user_roles = list(filter(lambda x: x != ',', user_roles))
                user_roles = [int(x) for x in user_roles]  # roles to be added

            current_user_roles = UserToUserRole.find_all_user_role_by_user_id(current_user.id)
            current_user_roles_id = list(map(lambda x: x.user_role_id, current_user_roles))  # existing roles

            if user_roles:
                for role_id in user_roles:
                    role = UserRole.find_by_id(role_id)

                    if role and role.role_name != "System" and role_id not in current_user_roles_id:
                        new_user_to_user_role = UserToUserRole(
                            user_id=current_user.id,
                            user_role_id=role_id
                        )
                        try:
                            new_user_to_user_role.save_to_db()
                        except Exception as exc:
                            new_user_to_user_role.rollback()
                            raise exc
                    else:
                        print(f"Error creating User to User Role relation: User Role with id ({role}) does not exist!")

            # Create preferences notifications
            np = NotificationPreferences.find_one(current_user.id)

            if not np:
                NotificationPreferences(user_id=current_user.id, sms=False, push=False, email=False, webhook=False).save()

            nas = NotificationAlertSettings.find_one(current_user.id)

            if not nas:
                NotificationAlertSettings(user_id=current_user.id, high=True, medium=True, low=True, info=True).save()

            dcs = DataCollector.find_by_user(current_user).items

            for dc in dcs:
                ndcs = NotificationDataCollectorSettings.find_one(current_user.id, dc.id)

                if not ndcs:
                    NotificationDataCollectorSettings(data_collector_id=dc.id, user_id=current_user.id,
                                                      enabled=True).save()

            nd = NotificationData.find_one(current_user.id)

            if not nd:
                NotificationData(user_id=current_user.id, last_read=datetime.datetime.now()).save()

            return jsonify({"message": "Password Changed Successfully"})
        except Exception as exc:
            LOG.error("Something went wrong trying to change the password: {0}".format(exc))

            return internal("Something went wrong trying to change the password")

class PasswordRecoveryAPI(Resource):
    def put(self):

        data = user_recover_password_parser.parse_args()
        user_list = User.find_by_email(data["username_or_email"])

        if user_list:
            current_user = user_list[0]
        else:
            current_user = User.find_by_username(data["username_or_email"])

        if USE_RECAPTCHA:
            recaptcha_valid= validate_recaptcha_token(data['recaptcha_token'])

            if not recaptcha_valid:
                LOG.debug('Got bad recaptcha token while triying to recover password')

                return internal("Got bad recaptcha token while triying to recover password")
        else:
            LOG.warning("Recaptcha was not validated because the credentials were not defined.")

        if current_user and current_user.active and not current_user.deleted:
            token = hashlib.sha256((current_user.full_name + str(datetime.datetime.now())).encode())
            encoded_token = token.hexdigest()

            try:
                password_reset_list = PasswordReset.find_active_tokens_by_user_id(current_user.id)

                for password_reset in password_reset_list:
                    password_reset.active = False
                    try:
                        password_reset.update_to_db()
                    except Exception as exc:
                        password_reset.rollback()
                        raise exc 

                new_password_reset = PasswordReset(
                    user_id=current_user.id,
                    token=encoded_token,
                    creation_date=datetime.datetime.now().isoformat(),
                    active=True
                )
                full_url = config.BRAND_URL + \
                           "change_password/" + str(encoded_token)

                if config.SMTP_HOST and config.SEND_EMAILS:
                    LOG.debug('init email sending')
                    msg = MIMEMultipart('alternative')
                    msg['Subject'] = f"{config.BRAND_NAME} Password Recovery"
                    msg['From'] = email.utils.formataddr((config.SMTP_SENDER_NAME, config.SMTP_SENDER))
                    msg['To'] = current_user.email
                    # msg['To'] = 'bounce@simulator.amazonses.com'
                    part = MIMEText(render_template(
                        'recovery.html',
                        brand_name=config.BRAND_NAME,
                        full_url=full_url
                        ), 'html')
                    msg.attach(part)
                    server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT)
                    # server.set_debuglevel(1)
                    server.ehlo()
                    server.starttls()
                    # stmplib docs recommend calling ehlo() before & after starttls()
                    server.ehlo()
                    server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
                    server.sendmail(config.SMTP_SENDER, current_user.email, msg.as_string())
                    # server.sendmail(config.SMTP_SENDER,'bounce@simulator.amazonses.com', msg.as_string())
                    server.close()
                    try:
                        new_password_reset.save_to_db()
                    except Exception as exc:
                        new_password_reset.rollback()
                        raise exc
                    LOG.debug("finished email sending")
                elif config.SEND_EMAILS:
                    LOG.error("Mail not sent since there is not SMTP server configured.")

                    return internal("Something went wrong trying to resend Password Recover")

            except Exception as exc:
                LOG.error(
                    "Something went wrong with Password Recovery: {0}".format(exc))

                return internal("Something went wrong with Password Recovery")


class ChangePasswordByRecoveryAPI(Resource):
    def put(self, token):
        data = user_change_password_by_recovery_parser.parse_args()
        password_reset = PasswordReset.find_by_token(token)

        if not password_reset:
            return internal("Invalid token")

        # password validation
        password_failed = validate_password(data["password"])

        if password_failed:
            return internal("Password {0} is not valid".format(data["password"]))

        # date validation
        token_time_valid = password_reset.creation_date > datetime.datetime.now(
            datetime.timezone.utc) - datetime.timedelta(hours=24)

        if not token_time_valid:
            password_reset.active = False
            try:
                password_reset.update_to_db()
            except Exception:
                password_reset.rollback()
                LOG.error(f"Couldn\'t save the data. Making a rollback")
            return internal("Invalid token")

        try:
            current_user = User.find_by_id(password_reset.user_id)
            current_user.password = User.generate_hash(data["password"])
            current_user.active = True
            current_user.blocked = False
            try:
                current_user.update_to_db()
            except Exception as exc:
                current_user.rollback()
                raise exc

            login_attempts = LoginAttempts.find_by_user(current_user.id)

            if login_attempts:
                login_attempts.attempts = 0
                login_attempts.last_attempt = datetime.datetime.now().isoformat()
                try:
                    login_attempts.update_to_db()
                except Exception as exc:
                    login_attempts.rollback()
                    raise exc

            password_reset_list = PasswordReset.find_active_tokens_by_user_id(password_reset.user_id)

            for password_reset in password_reset_list:
                password_reset.active = False
                try:
                    password_reset.update_to_db()
                except Exception as exc:
                    password_reset.rollback()
                    raise exc

            password_reset.active = False
            try:
                password_reset.update_to_db()
            except Exception as exc:
                password_reset.rollback()
                raise exc

            if config.SMTP_HOST and config.SEND_EMAILS:
                LOG.debug('init email sending')
                msg = MIMEMultipart('alternative')
                msg['Subject'] = f"{config.BRAND_NAME} Password Changed"
                msg['From'] = email.utils.formataddr((config.SMTP_SENDER_NAME, config.SMTP_SENDER))
                msg['To'] = current_user.email
                part = MIMEText(render_template(
                    'password_changed.html',
                    brand_name=config.BRAND_NAME,
                    full_url=config.BRAND_URL
                    ), 'html')
                msg.attach(part)
                server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT)
                # server.set_debuglevel(1)
                server.ehlo()
                server.starttls()
                # stmplib docs recommend calling ehlo() before & after starttls()
                server.ehlo()
                server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
                server.sendmail(config.SMTP_SENDER, current_user.email, msg.as_string())
                server.close()
                LOG.debug("finished email sending")

                return jsonify({"message": "Password Changed Successfully"})
            elif config.SEND_EMAILS:
                LOG.error("Mail not sent since there is not SMTP server configured.")

                return internal("Something went wrong trying to resend activation")

        except Exception as exc:
            LOG.error(
                "Something went wrong trying to change the password: {0}".format(exc))

            return internal("Something went wrong trying to change the password")


class ChangePasswordAPI(Resource):

    @jwt_required
    def put(self):
        current_user = User.find_by_username(get_jwt_identity())

        if not current_user:
            return internal("User {0} could not be found.".format(get_jwt_identity()))

        data = user_change_password_parser.parse_args()

        if not User.verify_hash(data["current_password"], current_user.password):
            return internal("Current password is wrong")

        # password validation
        password_failed = validate_password(data["password"]) #at this point, both passwords are the same

        if password_failed:
            return internal("Password {0} is not valid".format(data["password"]))

        try:
            current_user.password = User.generate_hash(data["password"])
            current_user.update_to_db()

            return jsonify({"message": "Password Changed Successfully"})
        except Exception as exc:
            current_user.rollback()
            LOG.error("Something went wrong trying to change the password: {0}".format(exc))

            return internal("Something went wrong trying to change the password")

class ChangeEmailRequestAPI(Resource):

    @jwt_required
    def post(self):
        current_user = User.find_by_username(get_jwt_identity())

        if not current_user:
            return internal("User {0} could not be found.".format(get_jwt_identity()))

        data = user_change_email_parser.parse_args()

        if not User.verify_hash(data["current_password"], current_user.password):
            return internal("Current password is wrong")

        email_without_space = data["email"].strip().lower()
        email_spaces = email_without_space.split(" ")

        if len(email_spaces) > 1:
            return internal("Email {} is not valid".format(email_without_space))

        is_valid = validate_email(email_without_space)

        if not is_valid:
            return internal("Email {} is not valid".format(email_without_space))

        list_email = User.find_by_email(email_without_space)

        if len(list_email) > 0:
            return internal("Email {0} is not available".format(email_without_space))

        try:
            token = hashlib.sha256((current_user.full_name + str(datetime.datetime.now())).encode())
            encoded_token = token.hexdigest()

            new_request = ChangeEmailRequests(
                user_id=current_user.id,
                new_email=email_without_space,
                old_email=current_user.email,
                token=encoded_token,
                creation_date=datetime.datetime.now().isoformat(),
                active=True
            )

            new_request_list = ChangeEmailRequests.find_active_tokens_by_user_id(current_user.id)

            for item in new_request_list:
                item.active = False
                try:
                    item.update_to_db()
                except Exception as exc:
                    item.rollback()
                    raise exc

            try:
                new_request.save_to_db()
            except Exception as exc:
                new_request.rollback()
                raise exc

            full_url = config.BRAND_URL + \
                       "change_email_request/" + str(encoded_token)

            if config.SMTP_HOST and config.SEND_EMAILS:
                LOG.debug('init email sending')
                msg = MIMEMultipart('alternative')
                msg['Subject'] = f"{config.BRAND_NAME} Change Email Request"
                msg['From'] = email.utils.formataddr((config.SMTP_SENDER_NAME, config.SMTP_SENDER))
                msg['To'] = current_user.email
                part = MIMEText(render_template(
                    'change_email_request.html',
                    brand_name=config.BRAND_NAME,
                    full_url=full_url
                    ), 'html')
                msg.attach(part)
                server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT)
                # server.set_debuglevel(1)
                server.ehlo()
                server.starttls()
                # stmplib docs recommend calling ehlo() before & after starttls()
                server.ehlo()
                server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
                server.sendmail(config.SMTP_SENDER, current_user.email, msg.as_string())
                server.close()
                LOG.debug("finished email sending")

                return jsonify({"message": "Email Request Sent Successfully"})
            elif config.SEND_EMAILS:
                LOG.error("Mail not sent since there is not SMTP server configured.")

                return internal("Something went wrong trying to resend activation")

        except Exception as exc:
            LOG.error("Something went wrong trying to change the email: {0}".format(exc))

            return internal("Something went wrong trying to change the email")


class ChangeEmailAPI(Resource):
    def put(self, token):
        change_email = ChangeEmailRequests.find_by_token(token)

        if not change_email:
            return internal("Invalid token")

        # date validation
        token_time_valid = change_email.creation_date > datetime.datetime.now(
            datetime.timezone.utc) - datetime.timedelta(hours=24)

        if not token_time_valid:
            change_email.active = False
            try:
                change_email.update_to_db()
            except Exception:
                change_email.rollback()
                LOG.error(f"Couldn\'t save email data. Making a rollback")
            return internal("Invalid token")

        try:
            current_user = User.find_by_id(change_email.user_id)
            current_user.email = change_email.new_email
            try:
                current_user.update_to_db()
            except Exception as exc:
                current_user.rollback()
                raise exc

            change_email.active = False
            try:
                change_email.update_to_db()
            except Exception as exc:
                change_email.rollback()
                raise exc

            return jsonify({"message": "E-mail Changed Successfully"})
        except Exception as exc:
            LOG.error(
                "Something went wrong trying to change the e-mail: {0}".format(exc))

            return internal("Something went wrong trying to change the password")


class Login(Resource):

    def post(self):
        data = login_parser.parse_args()
        user = User.find_by_username(data["username_or_email"])

        if user is None:
            user_list = User.find_by_email(data["username_or_email"])

            if user_list:
                user = user_list[0]

        if user is None or user.deleted or not user.active:
            return forbidden()

        if user.blocked:
            return forbidden()

        login_attempts = LoginAttempts.find_by_user(user.id)

        if User.verify_hash(data["password"], user.password):

            if login_attempts:
                login_attempts.attempts = 0
                login_attempts.last_attempt = datetime.datetime.now().isoformat()
                try:
                    login_attempts.update_to_db()
                except Exception:
                    login_attempts.rollback()
                    LOG.error(f"Couldn\'t update the number of login attempts. Making a rollback")
            else:
                login_attempts = LoginAttempts(
                    user_id=user.id,
                    attempts=0,
                    last_attempt=datetime.datetime.now().isoformat()
                )
                try:
                    login_attempts.save_to_db()
                except Exception:
                    login_attempts.rollback()
                    LOG.error(f"Couldn\'t save the number of login attempts. Making a rollback")

            access_token = create_access_token(identity=user)
            refresh_token = create_refresh_token(identity=user)

            return {
                "message": "Logged in as {}".format(user.username),
                "access_token": access_token,
                "refresh_token": refresh_token
            }
        else:
            if login_attempts:
                login_attempts.attempts += 1
                login_attempts.last_attempt = datetime.datetime.now().isoformat()
                try:
                    login_attempts.update_to_db()
                except Exception:
                    login_attempts.rollback()
                    LOG.error(f"Couldn\'t update the number of login attempts. Making a rollback")

                if login_attempts.attempts >= 5:
                    user.blocked = True
                    try:
                        user.update_to_db()
                    except Exception:
                        user.rollback()
                        LOG.error(f"Couldn\'t update user data. Making a rollback")

                    full_url = config.BRAND_URL + "recovery"

                    if config.SMTP_HOST and config.SEND_EMAILS:
                        LOG.debug('init email sending')
                        msg = MIMEMultipart('alternative')
                        msg['Subject'] = f"{config.BRAND_NAME} Account Blocked"
                        msg['From'] = email.utils.formataddr((config.SMTP_SENDER_NAME, config.SMTP_SENDER))
                        msg['To'] = user.email
                        part = MIMEText(render_template(
                            'blocked_account.html',
                            brand_name=config.BRAND_NAME,
                            full_url=full_url
                            ), 'html')
                        msg.attach(part)
                        server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT)
                        # server.set_debuglevel(1)
                        server.ehlo()
                        server.starttls()
                        # stmplib docs recommend calling ehlo() before & after starttls()
                        server.ehlo()
                        server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
                        server.sendmail(config.SMTP_SENDER, user.email, msg.as_string())
                        server.close()
                        LOG.debug("finished email sending")
                    elif config.SEND_EMAILS:
                        LOG.error("Mail not sent since there is not SMTP server configured.")

                        return internal("Something went wrong trying to resend activation")
            else:
                login_attempts = LoginAttempts(
                    user_id=user.id,
                    attempts=1,
                    last_attempt=datetime.datetime.now().isoformat()
                )

                try:
                    login_attempts.save_to_db()
                except Exception:
                    login_attempts.rollback()
                    LOG.error(f"Couldn\'t save the number of login attempts. Making a rollback")

            return make_response(jsonify({"error": "forbidden access"}), 403)


class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()

            return jsonify({"message": "Access token has been revoked"})

        except Exception as exc:
            LOG.error("Error trying to save an Token: {0}".format(exc))

            return internal("Something went wrong with Access Token")


class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()

            return {"message": "Refresh token has been revoked"}
        except Exception as exc:
            LOG.error("Error trying to save an Token: {0}".format(exc))

            return internal("Something went wrong with Access Token")

def validate_recaptcha_token(recaptcha_response):
    uri_recaptcha = 'https://www.google.com/recaptcha/api/siteverify'
    recaptcha_sitekey = os.environ['RECAPTCHA_SECRET_KEY']

    params = urlencode({
            'secret': recaptcha_sitekey,
            'response': recaptcha_response,
            # 'remote_ip': remote_ip,
            })

    data = urlopen(uri_recaptcha, params.encode('utf-8')).read()
    result = json.loads(data)
    success = result.get('success', None)

    if success == True:
        LOG.debug('reCaptcha passed')

        return success
    else:
        LOG.debug('reCaptcha failed')

        return False

class Register(Resource):

    @jwt_optional
    def post(self):
        """Registers the user."""
        """If you alter the response message take note that you need to modify the front end."""
        admin_user_identity = get_jwt_identity()
        data = register_parser.parse_args()

        # If it's an internal request, check it's coming from an admin. Otherwise, validate recaptcha

        if admin_user_identity is not None:
            if not is_admin_user(User.find_by_username(get_jwt_identity()).id):
                raise Error.Forbidden()
        elif USE_RECAPTCHA:
            recaptcha_token = data['recaptcha_token']

            if not recaptcha_token:
                raise Error.InvalidUsage('Missing recaptcha token in request')
            recaptcha_valid = validate_recaptcha_token(recaptcha_token)

            if not recaptcha_valid:
                raise Error.InvalidUsage('Invalid recaptcha token')
        else:
            LOG.warning("Recaptcha was not validated because the credentials were not defined.")

        user_roles = []
        organization_id = None

        if admin_user_identity is None: # Creating new user from land page
            user_roles = [2]
        else: # Creating new user into an existing organization
            if not "user_roles" in data or data["user_roles"] is None or len(data["user_roles"]) == 0:
                raise Error.InvalidUsage("Missing user_roles attribute.")

            if len(data["user_roles"]) > 1:
                raise Error.InvalidUsage("Cannot assign more than one role")

            if int(data["user_roles"][0]) not in [1, 2]:
                raise Error.InvalidUsage("Cannot assign this user role")


            admin_user = User.find_by_username(admin_user_identity)
            user_roles = data["user_roles"]
            organization_id = admin_user.organization_id

        email_without_space = data["email"].strip().lower()
        email_spaces = email_without_space.split(" ")

        if len(email_spaces) > 1:
            raise Error.InvalidUsage("Email {0} is not valid".format(email_without_space))

        is_valid = validate_email(email_without_space)

        if not is_valid:
            raise Error.InvalidUsage("Email {0} is not valid".format(email_without_space))

        username_without_space = data["username"].strip()
        username_spaces = username_without_space.split(" ")

        if len(username_spaces) > 1:
            raise Error.InvalidUsage("User {0} is not valid".format(username_without_space))

        if User.find_by_username(username_without_space):
            raise Error.InvalidUsage("User {0} already exists".format(username_without_space))
        phone_without_space = None

        if data["phone"]:
            phone_without_space = data["phone"].strip()  # delete whitespaces in phone (leading and trailing)

            phone_spaces = phone_without_space.split(" ")

            if len(phone_spaces) > 1:
                raise Error.InvalidUsage("Phone {0} is not valid".format(phone_without_space))

            phone_without_prefix = ""
            phone_prefix = ""

            if len(phone_without_space.split("-"))>1:
                phone_without_prefix = phone_without_space.split("-")[1]
                phone_prefix = phone_without_space.split("-")[0]
            # if len(phone_without_space) > 0 and not phone_without_space.isdigit():
            phone_without_space_and_signs = phone_without_space.replace('+', '', 1)
            phone_without_space_and_signs = phone_without_space_and_signs.replace('-', '', 1)

            if len(phone_without_space) > 0 and (
                    not phone_without_space.count("+") == 1 or
                    not phone_without_space.count("-") == 1 or
                    not phone_without_space_and_signs.isdigit() or
                    len(phone_without_prefix) < 6 or
                    len(phone_prefix) < 2 or
                    phone_without_space.find("+") != 0 or
                    len(phone_without_space) > 30):
                raise Error.InvalidUsage("Phone {0} is not valid".format(phone_without_space))

        list_user = User.find_by_email(email_without_space)

        if len(list_user) == 0:

            collectors = []

            if "data_collectors" in data and data["data_collectors"] is not None and len(data["data_collectors"]) > 0:
                collector_id_strings = data["data_collectors"]
                collector_ids = list(map(lambda x: int(x), collector_id_strings))
                collectors = DataCollector.find_by_ids_in_org(collector_ids, user.organization_id)

            user = User(
                username=username_without_space.lower(),
                full_name=data["full_name"],
                password="passwordArgeniss",
                email=email_without_space,
                phone=phone_without_space,
                organization_id=organization_id,
                deleted=False,
                collectors=collectors
            )
            try:
                user.save_to_db()
            except Exception:
                user.rollback()
                LOG.error(f"Couldn\'t create the new User. Making a rollback")
            

        elif len(list_user) > 0:

            user= list_user[0]
            # If user exists and is active, then send a recovery mail

            if user.active:
                if config.SMTP_HOST and config.SEND_EMAILS:

                    full_url = config.BRAND_URL + "recovery/"

                    LOG.debug('init email sending')
                    msg = MIMEMultipart('alternative')
                    msg['Subject'] = f"{config.BRAND_NAME} Existing Account"
                    msg['From'] = email.utils.formataddr((config.SMTP_SENDER_NAME, config.SMTP_SENDER))
                    msg['To'] = email_without_space
                    part = MIMEText(render_template(
                        'existing_account.html',
                        brand_name=config.BRAND_NAME,
                        full_url=full_url
                        ), 'html')
                    msg.attach(part)
                    server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT)
                    # server.set_debuglevel(1)
                    server.ehlo()
                    server.starttls()
                    # stmplib docs recommend calling ehlo() before & after starttls()
                    server.ehlo()
                    server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
                    server.sendmail(config.SMTP_SENDER, email_without_space, msg.as_string())
                    server.close()
                    LOG.debug("finished email sending")

                    return {
                        "message": "An email was sent to the account provided"
                    }
                elif config.SEND_EMAILS:
                    raise Error.Internal("Something went wrong trying to send mail: " + \
                        "Existing account mail not sent because there is no SMTP server configured.")

        # If user didn't exist or existed but wasn't activated, then send  an activation mail
        token = hashlib.sha256((user.email + str(datetime.datetime.now())).encode())
        encoded_token = token.hexdigest()

        new_account_activation = AccountActivation(
            user_id=user.id,
            token=encoded_token,
            creation_date=datetime.datetime.now().isoformat(),
            active=True,
            user_roles_id=",".join([str(x) for x in user_roles])
        )

        full_url = config.BRAND_URL + "activation/" + str(encoded_token)

        if config.SMTP_HOST and config.SEND_EMAILS:
            LOG.debug('init email sending')
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"{config.BRAND_NAME} Account Confirmation"
            msg['From'] = email.utils.formataddr((config.SMTP_SENDER_NAME, config.SMTP_SENDER))
            msg['To'] = user.email
            part = MIMEText(render_template(
                'activation.html',
                brand_name=config.BRAND_NAME,
                full_url=full_url
                ), 'html')
            msg.attach(part)
            server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT)
            server.ehlo()
            server.starttls()
            # stmplib docs recommend calling ehlo() before & after starttls()
            server.ehlo()
            server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
            server.sendmail(config.SMTP_SENDER, user.email, msg.as_string())
            server.close()
            LOG.debug("finished email sending")
            try:
                new_account_activation.save_to_db()
            except Exception:
                new_account_activation.rollback()
                LOG.error(f"Couldn\'t save the new account activation. Making a rollback")

            return {
                "message": "An email was sent to the account provided"
            }
        elif config.SEND_EMAILS:
            raise Error.InvalidUsage("Something went wrong trying to send activation: " + \
                "Activation mail not sent because there is no SMTP server configured.")



class TokenRefresh(Resource):

    @jwt_refresh_token_required
    def post(self):
        current_user_username = get_jwt_identity()
        current_user = User.find_by_username(current_user_username)
        access_token = create_access_token(identity=current_user)

        return jsonify({"access_token": access_token})


class UserCount(Resource):

    @jwt_required
    def get(self):
        user = User.find_by_username(get_jwt_identity())

        if not user:
            return forbidden()

        if is_admin_user(user.id):
            user_count = User.get_count_all()
        else:
            user_count = User.get_count_by_organization_id(user.organization_id)

        return jsonify({"user_count": user_count})


class UserRoleListAPI(Resource):
    @jwt_required
    def get(self):
        user = User.find_by_username(get_jwt_identity())

        if not user:
            return forbidden()

        if not is_admin_user(user.id):
            user_roles = UserToUserRole.find_all_user_role_by_user_id(user.id)
            return_list = []

            for user_role in user_roles:
                return_list.append(UserRole.find_by_id(user_role.user_role_id).to_json())

            return {"user_roles": return_list}

        try:
            if is_admin_user(user.id):
                return UserRole.return_all(True)
            else:
                limited_user_roles_list = []
                user_roles = UserRole.return_all(True)
                user_roles_list = user_roles["user_roles"]

                for user_role in user_roles_list:
                    user_role_id = user_role["id"]

                    if not user_role_id == UserRole.find_by_role_name(RoleTypes.User_Admin.value).id:
                        limited_user_roles_list.append(user_role)

                return {"user_roles": limited_user_roles_list}

        except Exception as exc:
            LOG.error("Error trying to retrieve UserRoles: {0}".format(exc))

            return internal("Error trying to retrieve the UserRoles")


class DataCollectorAPI(Resource):

    @jwt_required
    def put(self, data_collector_id):
        user = User.find_by_username(get_jwt_identity())

        if not user or not is_admin_user(user.id):
            return forbidden()
        data_collector = DataCollector.find_by_id(data_collector_id)

        if not data_collector:
            return not_found()

        if user.organization_id != data_collector.organization_id:
            return forbidden()

        data = data_collector_parser.parse_args()

        gateway_id = data.gateway_id
        type_id = data.data_collector_type_id
        type = DataCollectorType.find_one(type_id)

        if not type:
            return bad_request('Invalid data_collector_type_id')

        # This section is commented since now it is allowed to enter an IP and a port for TTNv3 connections

        #if type.type == TTN_COLLECTOR:
        #    if data.port or data.ip:
        #        return bad_request('Not allowed ip and port in ttn_collector type')
        #elif type.type == TTN_V3_COLLECTOR:
        #    if data.port or data.ip or data.user or data.password:
        #        return bad_request('Not allowed ip, port, user or password in ttn_v3_collector type')
        #else:

        # Check if port is valid

        try:
            if not (0 < int(data.port, 10) <= 65536):
                return bad_request('Port invalid')
        except Exception as exc:
            return bad_request('Port invalid')

        # Check if URL or IP are valid

        if not validators.url(data.ip):
            try:
                socket.inet_aton(data.ip)
            except socket.error:
                if not validators.domain(data.ip):
                    return bad_request('IP invalid')
        else:
            try:
                validators.url(data.ip)
            except: return bad_request('URL invalid')

        if len(data.description) > 1000:
            return bad_request('Description field too long. Max is 1000 characters.')

        if len(data.name) > 120:
            return bad_request('Name field too long. Max is 120 characters.')

        policy_id = data.policy_id
        policy = Policy.find_one(policy_id)

        if policy.organization_id is not None and policy.organization_id != user.organization_id:
            return bad_request('Not allowed policy.')

        changed_policy = False

        if data_collector.policy_id != policy_id:
            changed_policy = True

        data.ca_cert = data.ca_cert != "" and data.ca_cert or None
        data.client_cert = data.client_cert != "" and data.client_cert or None
        data.client_key = data.client_key != "" and data.client_key or None

        cryptedPassword = None

        if data.password:
            uncryptedPassword = bytes(data.password, 'utf-8')
            cryptedPassword = cipher_suite.encrypt(uncryptedPassword).decode('utf8')
        
        cryptedApiKey = None

        if data.gateway_api_key:
            uncryptedApiKey = bytes(data.gateway_api_key, 'utf-8')
            cryptedApiKey = cipher_suite.encrypt(uncryptedApiKey).decode('utf8')

        try:
            data_collector.name = data.name,
            data_collector.description = data.description,
            data_collector.ip = data.ip,
            data_collector.port = data.port,
            data_collector.user = data.user,
            data_collector.ssl = data.ssl == 'True'
            data_collector.ca_cert = data.ca_cert
            data_collector.client_cert = data.client_cert
            data_collector.client_key = data.client_key
            data_collector.password = cryptedPassword
            data_collector.data_collector_type_id = type_id
            data_collector.policy_id = policy_id
            data_collector.gateway_id = gateway_id
            data_collector.gateway_name = data.gateway_name,
            data_collector.gateway_api_key = cryptedApiKey,
            data_collector.region_id = data.region_id,
            try:
                data_collector.update_to_db()
            except Exception as exc:
                data_collector.rollback()
                raise exc

            topics = MqttTopic.find_by_data_collector_id(data_collector_id)

            for topic in topics:
                try:
                    topic.delete_from_db()
                except Exception as exc:
                    topic.rollback()
                    raise exc   

            if data['topics']:
                for topic in data['topics']:
                    new_mqtt_topic = MqttTopic(
                        name=topic,
                        data_collector_id=data_collector.id
                    )
                    try:
                        new_mqtt_topic.save_to_db()
                    except Exception as exc:
                        new_mqtt_topic.rollback()
                        raise exc

            emit_data_collector_event('UPDATED', data_collector.to_json())

            if changed_policy:
                emit_policy_event('UPDATED', {'id': policy_id})

            parameters = {
                'ip': data_collector.ip,
                'port': data_collector.port,
                'user': data_collector.user,
                'ssl': data_collector.ssl,
                'type': data_collector.type.name,
                'policy': data_collector.policy.name
            }
            log_event = DataCollectorLogEvent(
                data_collector_id=data_collector.id,
                created_at=datetime.datetime.now(),
                parameters=json.dumps(parameters),
                type=DataCollectorLogEventType.UPDATED,
                user_id=user.id
            )
            log_event.save()

            return jsonify({"message": "Data Collector Updated Successfully", "id": data_collector.id})

        except Exception as exc:
            LOG.error("Something went wrong trying to update the Data Collector: {0}".format(exc))

            return internal("Something went wrong trying to update the Data Collector: {0}".format(exc))

    @jwt_required
    def get(self, data_collector_id):
        user = User.find_by_username(get_jwt_identity())

        if not user or not is_regular_user(user.id) and not is_admin_user(user.id):
            return forbidden()
        data_collector = DataCollector.find_by_id(data_collector_id)

        if not data_collector:
            return not_found()

        if user.organization_id != data_collector.organization_id:
            return forbidden()

        min_date = datetime.datetime.today() - datetime.timedelta(hours=4)
        result = Packet.find_max_by_organization_id(data_collector.organization_id, min_date)
        result = list(filter(lambda item: item.data_collector_id == data_collector.id, result))
        max_date = None

        if len(result) > 0:
            max_date = result[0].date
        response = data_collector.to_json()
        response['lastMessage'] = "{}".format(max_date) if max_date else None

        return response, 200

    @jwt_required
    def delete(self, data_collector_id):
        user = User.find_by_username(get_jwt_identity())

        if not user or not is_admin_user(user.id):
            return forbidden()
        data_collector = DataCollector.find_by_id(data_collector_id)

        if not data_collector:
            return not_found()

        if user.organization_id != data_collector.organization_id:
            return forbidden()

        topics = MqttTopic.find_by_data_collector_id(data_collector_id)

        for topic in topics:
            try:
                topic.delete_from_db()
            except Exception:
                topic.rollback()
                LOG.error(f"Couldn\'t delete the topic with id {topic}. Making a rollback")
        try:
            data_collector.delete_from_db()
        except Exception:
            data_collector.rollback()
            LOG.error("Couldn\'t delete the data collector. Making a rollback")
        emit_data_collector_event('DELETED', data_collector.to_json())

        # Create log event
        parameters = {}
        log_event = DataCollectorLogEvent(
            data_collector_id=data_collector.id,
            created_at=datetime.datetime.now(),
            parameters=json.dumps(parameters),
            type=DataCollectorLogEventType.DELETED,
            user_id=user.id
        )
        log_event.save()

        # Delete preference item for user notifications
        NotificationDataCollectorSettings.delete_by_criteria(data_collector_id=data_collector.id, user_id=None)

        return jsonify({"message": "Data Collector Removed Successfully", "id": data_collector.id})

    @jwt_required
    def patch(self, data_collector_id):
        user = User.find_by_username(get_jwt_identity())

        if not user or not is_admin_user(user.id):
            return forbidden()
        data_collector = DataCollector.find_by_id(data_collector_id)

        if not data_collector:
            return not_found()

        if user.organization_id != data_collector.organization_id:
            return forbidden()

        body = json.loads(request.data)
        status = body.get('status')

        if status not in ['DISABLED', 'ENABLED']:
            return [{'code': 'INVALID_STATUS', 'message': 'Invalid status'}], 400

        if status == 'DISABLED':
            if data_collector.status == DataCollectorStatus.CONNECTED or data_collector.status == DataCollectorStatus.DISCONNECTED:
                status = DataCollectorStatus.DISABLED
            else:
                return [{'code': 'FORBIDDEN_STATUS', 'message': 'Forbidden status'}], 400
        else:
            if data_collector.status == DataCollectorStatus.DISABLED:
                status = DataCollectorStatus.DISCONNECTED
            else:
                return [{'code': 'FORBIDDEN_STATUS', 'message': 'Forbidden status'}], 400

        try:
            data_collector.status = status
            try:
                data_collector.update_to_db()
            except Exception as exc:
                data_collector.rollback()
                raise exc
            response = data_collector.to_json()

            if status == DataCollectorStatus.DISCONNECTED:
                emit_data_collector_event('ENABLED', response)
                parameters = {}
                log_event = DataCollectorLogEvent(
                    data_collector_id=data_collector.id,
                    created_at=datetime.datetime.now(),
                    parameters=json.dumps(parameters),
                    type=DataCollectorLogEventType.ENABLED,
                    user_id=user.id
                )
                log_event.save()
            else:
                emit_data_collector_event('DISABLED', response)
                parameters = {}
                log_event = DataCollectorLogEvent(
                    data_collector_id=data_collector.id,
                    created_at=datetime.datetime.now(),
                    parameters=json.dumps(parameters),
                    type=DataCollectorLogEventType.DISABLED,
                    user_id=user.id
                )
                log_event.save()

            return response, 200
        except Exception as exc:
            LOG.error('Something went wrong trying to update data collector: {0}'.format(exc))

            return None, 500


class DataCollectorListAPI(Resource):

    @jwt_required
    def post(self):
        """
        Creates a new DataCollector
        - parses and validates parameters
        - save the definition to db table data_collectors
        - send a message 'CREATED' to Orchestrator through queue 'data_collectors_events'
        - saves a DataCollectorLogEvent record
        - saves a NotificationDataCollectorSettings record for each user
        Returns a json with
            id: data collector id
            message: 'Data Collector Added Successfully'
        """
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id):
            return forbidden()

        data = data_collector_parser.parse_args()
        organization_id = user.organization_id
        gateway_id = data.gateway_id
        custom_ip = data.custom_ip == 'true'
        type_id = data.data_collector_type_id

        if not type_id:
            return bad_request('Expecting data_collector_type_id')

        type = DataCollectorType.find_one(type_id)

        if not type:
            return bad_request('Invalid data_collector_type_id')

        # This section is commented since now it is allowed to enter an IP and a port for TTNv3 connections
        
        #if type.type == TTN_COLLECTOR:
        #    if data.port or data.ip:
        #        return bad_request('Not allowed ip and port in ttn_collector type')
        #elif type.type == TTN_V3_COLLECTOR:
        #    if data.port or data.ip or data.user or data.password:
        #        return bad_request('Not allowed ip, port, user or password in ttn_v3_collector type')
        
        

        if not (type.type == TTN_V3_COLLECTOR and not custom_ip):
            
            # Check if port is valid
            
            try:
                if not (0 < int(data.port, 10) <= 65536):
                    return bad_request('Port invalid')
            except Exception as exc:
                return bad_request('Port invalid')

            # Check if URL or IP are valid

            if not validators.url(data.ip):
                try:
                    socket.inet_aton(data.ip)
                except socket.error:
                    if not validators.domain(data.ip):
                        return bad_request('IP invalid')
            else:
                try:
                    validators.url(data.ip)
                except: return bad_request('URL invalid')

        if len(data.description) > 1000:
            return bad_request('Description field too long. Max is 1000 characters.')

        if len(data.name) > 120:
            return bad_request('Description field too long. Max is 120 characters.')

        policy_id = data.policy_id
        policy = Policy.find_one(policy_id)

        if policy.organization_id is not None and policy.organization_id != user.organization_id:
            return bad_request('Not allowed policy.')

        cryptedPassword = None

        if data.password:
            uncryptedPassword = bytes(data.password, 'utf-8')
            cryptedPassword = cipher_suite.encrypt(uncryptedPassword).decode('utf8')

        cryptedApiKey = None
        if data.gateway_api_key:
            uncryptedApiKey = bytes(data.gateway_api_key, 'utf-8')
            cryptedApiKey = cipher_suite.encrypt(uncryptedApiKey).decode('utf8')
        try:
            gateways_list = []
            if type.type == TTN_V3_COLLECTOR:
                gateway_ids = [gtw.strip() for gtw in data.gateway_id.split(",")]
                gateway_names = [gtw.strip() for gtw in data.gateway_name.split(",")]
                gateways_list = [DataCollectorGateway(gateway_id=gateway_ids[i],gateway_name=gateway_names[i]) for i in range(0,len(gateway_ids))]

            new_data_collector = DataCollector(
                name=data.name,
                type=type,
                description=data.description,
                ip=data.ip,
                created_at=datetime.datetime.now(),
                port=data.port,
                user=data.user,
                password=cryptedPassword,
                ssl=data.ssl == 'True',
                policy_id=policy_id,
                organization_id=organization_id,
                ca_cert=data.ca_cert,
                client_cert=data.client_cert,
                client_key=data.client_key,
                data_collector_type_id=type_id,
                gateway_id=gateway_id,
                gateway_name=data.gateway_name,
                gateway_api_key=cryptedApiKey,
                region_id=data.region_id,
                status=DataCollectorStatus.DISCONNECTED,
                gateways_list=gateways_list
            )
            try:
                new_data_collector.save_to_db()
            except Exception as exc:
                new_data_collector.rollback()
                raise exc

            if data['topics']:
                for topic in data['topics']:
                    new_mqtt_topic = MqttTopic(
                        name=topic,
                        data_collector_id=new_data_collector.id
                    )
                    try:
                        new_mqtt_topic.save_to_db()
                    except Exception as exc:
                        new_mqtt_topic.rollback()
                        raise exc
            emit_data_collector_event('CREATED', new_data_collector.to_json())

            # Create log event
            parameters = {
                'ip': new_data_collector.ip,
                'port': new_data_collector.port,
                'user': new_data_collector.user,
                'ssl': new_data_collector.ssl,
                'type': new_data_collector.type.name,
                'policy': new_data_collector.policy.name
            }
            log_event = DataCollectorLogEvent(
                data_collector_id=new_data_collector.id,
                created_at=datetime.datetime.now(),
                parameters=json.dumps(parameters),
                type=DataCollectorLogEventType.CREATED,
                user_id=user.id
            )
            log_event.save()

            # Create preference item for user notifications
            users = User.find_all_user_by_organization_id(organization_id)
            # print(users)

            for user in users:
                NotificationDataCollectorSettings(
                    enabled=True,
                    user_id=user.id,
                    data_collector_id=new_data_collector.id
                ).save()

            return jsonify({"message": "Data Collector Added Successfully", "id": new_data_collector.id})

        except Exception as exc:
            LOG.error("Something went wrong trying to add the Data Collector: {0}".format(exc))

            return internal("Something went wrong trying to add the Data Collector: {0}".format(exc))

    @jwt_required
    def get(self):
        LOG.info("data collector list")
        try:
            user_identity = get_jwt_identity()
            user = User.find_by_username(user_identity)

            if not user or not is_admin_user(user.id) and not is_system(user.id) and not is_regular_user(user.id):
                return forbidden()

            page = request.args.get('page', default=1, type=int)
            size = request.args.get('size', default=1000, type=int)
            include_count = request.args.get('include_count') == 'true'
            types = request.args.getlist('type[]')
            resolved = request.args.get('resolved')
            risks = request.args.getlist('risk[]')
            data_collectors = request.args.getlist('data_collector[]')
            is_user_system = is_system(user.id)

            if resolved:
                resolved = resolved == 'true'

            if include_count:
                _from = request.args.get('from')
                to = request.args.get('to')
                counts = DataCollector.find_and_count_all(user, _from, to, types, resolved, risks, data_collectors)
                result = DataCollector.find_by_user(user, page, size)
                data_collectors = result.items
                headers = {'total-pages': result.pages, 'total-items': result.total}
                response = []

                for dc in data_collectors:
                    parsed_dc = dc.to_json_for_list()
                    found_counts = list(filter(lambda item: item.id == dc.id, counts))

                    if len(found_counts) > 0:
                        parsed_dc['count'] = found_counts[0].count
                    else:
                        parsed_dc['count'] = 0
                    response.append(parsed_dc)

                return {"data_collectors": response}, 200, headers
            else:
                result = DataCollector.find_by_user(user, page, size)
                data_collector_list = result.items
                headers = {'total-pages': result.pages, 'total-items': result.total}

                if is_user_system:
                    return {"data_collectors": list(
                        map(lambda data_collector: data_collector.to_json_for_system(), data_collector_list))}, 200, headers
                else:
                    return {"data_collectors": list(
                        map(lambda data_collector: data_collector.to_json_for_list(), data_collector_list))}, 200, headers
        except Exception as exc:
            import sys
            _, exc_obj, exc_tb = sys.exc_info()
            LOG.debug("Exception: {} - {}".format(exc_obj, exc_tb.tb_lineno))
            LOG.error("Something went wrong trying to get the Data Collector list: {0}".format(exc))

            return internal("Something went wrong trying to get the Data Collector list: {0}".format(exc))



class DataCollectorTestAPI(Resource):
    @jwt_required
    def get(self):
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id):
            return forbidden()

        data_collector_id = request.args.get('data_collector_id')

        if data_collector_id:
            try:
                key = 'TestResponse-' + data_collector_id
                event = GlobalData.find_by_key(key)

                if event:
                    data = json.loads(event.value)
                    data['haveResponse'] = True

                    return jsonify(data)
            except TypeError as e:
                LOG.error(f"Error: {e}")

        return jsonify({"haveResponse":False, "type":"NOTREADY", "message": "No response from connection test yet"})


    @jwt_required
    def post(self):
        LOG.info('Testing connection to new collector')
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id):
            return forbidden()

        data = data_collector_parser.parse_args()
        organization_id = user.organization_id
        gateway_id = data.gateway_id
        gateway_name = data.gateway_name
        region_id = data.region_id
        # data verification
        type_id = data.data_collector_type_id

        if not type_id:
            return bad_request('Expecting data_collector_type_id')

        type = DataCollectorType.find_one(type_id)

        if not type:
            return bad_request('Invalid data_collector_type_id')

        # This section is commented since now it is allowed to enter an IP and a port for TTNv3 connections

        #if type.type == TTN_COLLECTOR:
        #    if data.port or data.ip:
        #        return bad_request('Not allowed ip and port in ttn_collector type')
        #elif type.type == TTN_V3_COLLECTOR:
        #    if data.port or data.ip or data.user or data.password:
        #        return bad_request('Not allowed ip, port, user or password in ttn_v3_collector type')
        #else:
        
        # Check if port is valid

        
        try:
            if data.port and not (0 < int(data.port, 10) <= 65536):
                return bad_request('Port invalid')
        except Exception as exc:
            LOG.error(exc)
            return bad_request('Port invalid')
        

        # Check if URL or IP are valid 

        
        if not validators.url(data.ip):
            try:
                socket.inet_aton(data.ip)
            except socket.error:
                LOG.error(socket.error)
                if not validators.domain(data.ip):
                    return bad_request('IP invalid')
        else:
            try:
                validators.url(data.ip)
            except: 
                return bad_request('URL invalid')

        if len(data.description) > 1000:
            return bad_request('Description field too long. Max is 1000 characters.')

        if len(data.name) > 120:
            return bad_request('Description field too long. Max is 120 characters.')

        policy_id = data.policy_id
        policy = Policy.find_one(policy_id)

        if policy.organization_id is not None and policy.organization_id != user.organization_id:
            return bad_request('Not allowed policy.')

        cryptedPassword = None

        if data.password:
            uncryptedPassword = bytes(data.password, 'utf-8')
            cryptedPassword = cipher_suite.encrypt(uncryptedPassword).decode('utf8')

        cryptedApiKey = None

        if data.gateway_api_key:
            uncryptedApiKey = bytes(data.gateway_api_key, 'utf-8')
            cryptedApiKey = cipher_suite.encrypt(uncryptedApiKey).decode('utf8')

        # create new data collector
        try:
            collector_id = str(uuid.uuid4())
            LOG.debug(f"Collector id: {collector_id}")
            new_data_collector = DataCollector(
                name=data.name,
                type=type,
                description=data.description,
                ip=data.ip,
                created_at=datetime.datetime.now(),
                port=data.port,
                user=data.user,
                ca_cert=data.ca_cert,
                client_cert=data.client_cert,
                client_key=data.client_key,
                password=cryptedPassword,
                ssl=data.ssl == 'True',
                policy_id=policy_id,
                organization_id=organization_id,
                data_collector_type_id=type_id,
                gateway_id=gateway_id,
                gateway_name=gateway_name,
                gateway_api_key=cryptedApiKey,
                region_id=region_id,
                status=DataCollectorStatus.DISCONNECTED,
                id=collector_id
                # record is not saved to db so we don't have an autoincremental id; create a random uuid instead
            )

            if data['topics']:
                for topic in data['topics']:
                    new_mqtt_topic = MqttTopic(
                        name=topic,
                        data_collector_id=new_data_collector.id
                    )

                    try:
                        new_mqtt_topic.save_to_db()
                    except Exception as exc:
                        new_mqtt_topic.rollback()
                        raise exc

            emit_data_collector_event('TEST', new_data_collector.to_json())

            return jsonify({"message": "Testing data collector", "id": new_data_collector.id})

        except Exception as exc:
            LOG.error("Something went wrong trying to add the Data Collector: {0}".format(exc))

            return internal("Something went wrong trying to add the Data Collector: {0}".format(exc))


class DataCollectorsCountAPI(Resource):

    @jwt_required
    def get(self):
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return forbidden()

        return {
            'count': DataCollector.count_exclude_disabled(user)
        }


class DataCollectorTypesAPI(Resource):

    @jwt_required
    def get(self):
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return forbidden()

        types = DataCollectorType.find_all()

        return list(map(lambda type: type.to_json(), types))

class DataCollectorTTNAccount(Resource):
    @jwt_required
    def post(self):
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id):
            return forbidden()

        data = ttn_credentials_parser.parse_args()
        ttn_user = data["username"]
        ttn_password = data["password"]

        if not ttn_user or not ttn_password:
            return bad_request("TTN credentials not provided")

        ses = requests.Session()
        ses.headers['Content-type'] = 'application/json'
        res = ses.post('https://account.thethingsnetwork.org/api/v2/users/login', data=json.dumps({"username": ttn_user, "password": ttn_password}))
        ses.get('https://console.thethingsnetwork.org/login')

        if res.status_code != 200:
            return internal("Login failed with provided credentials")

        data_access = ses.get('https://console.thethingsnetwork.org/refresh', timeout=30)

        if data_access.status_code != 200:
            return internal("couldn't get TTN access data")

        access_token = data_access.json().get('access_token')
        res = ses.get('https://console.thethingsnetwork.org/api/gateways', headers={'Authorization': 'Bearer {}'.format(access_token)}, timeout=30)

        session['ttn_v2_user_gateways'] = [{"id":gateway.get('id'), "description":gateway.get('attributes').get('description')} for gateway in res.json()]

        return jsonify({"message": "Credentials processed successfully"})

class DataCollectorUserGateways(Resource):
    @jwt_required
    def get(self):
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return forbidden()

        user_gateways = session.get('ttn_v2_user_gateways')

        if not user_gateways:
            return not_found()

        return user_gateways

class DataCollectorTTN3Gateways(Resource):
    @jwt_required
    def get(self):
        '''
        This function retrieves all the gateways that can be accessed by the api_key and region_id provided.
        '''
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id):
            return forbidden()
        
        ttn3_credentials_parser = reqparse.RequestParser()
        ttn3_credentials_parser.add_argument('gateway_api_key',dest='gateway_api_key',required=True)
        ttn3_credentials_parser.add_argument('region_id',dest='region_id',required=True,type=int)
        data = ttn3_credentials_parser.parse_args()
        ttn3_api_key = data['gateway_api_key']
        ttn3_region_id = data['region_id']

        ses = requests.Session()
        ses.headers['Content-type'] = 'application/json'
            
        url = ''
        if ttn3_region_id == 1:
            url = 'https://eu1.cloud.thethings.network/api/v3/gateways'
        elif ttn3_region_id == 2:
            url = 'https://nam1.cloud.thethings.network/api/v3/gateways'
        elif ttn3_region_id == 3:
            url = 'https://au1.cloud.thethings.network/api/v3/gateways'
            
        res = ses.get(url, headers={'Authorization': 'Bearer {}'.format(ttn3_api_key)}, timeout=30)

        gateways_list = []
        gateways = res.json()['gateways']
        for gtw in gateways:
            gateways_list.append({"id":gtw['ids']['gateway_id'], "eui": gtw['ids']['eui']})

        return gateways_list

class DataCollectorTTNRegionsAPI(Resource):

    @jwt_required
    def get(self):
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return forbidden()

        regions = TTNRegion.find_all()

        return list(map(lambda region: region.to_json(), regions))

class DevicesListAPI(Resource):

    @jwt_required
    def get(self):

        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return forbidden()

        organization_id = user.organization_id
        since = request.args.get('last_up_timestamp[gte]')
        until = request.args.get('last_up_timestamp[lte]')
        page = request.args.get('page')
        size = request.args.get('size')

        if since:
            try:
                since = dp.parse(since)
            except Exception:
                return bad_request('no valid last_up_timestamp[gte] value')

        if until:
            try:
                until = dp.parse(until)
            except Exception:
                return bad_request('no valid last_up_timestamp[lte] value')

        if since and until and since > until:
            return bad_request('since value must be before to until value')

        if page:
            try:
                page = int(page)
            except Exception:
                return bad_request('no valid page value')
        else:
            page = 0

        if size:
            try:
                size = int(size)
            except Exception:
                return bad_request('no valid size value')
        else:
            size = 20

        devices = Device.find(organization_id, since, until, page, size)

        return list(map(lambda device: device.to_json(), devices))


class DevicesListCountAPI(Resource):

    @jwt_required
    def get(self):

        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return forbidden()

        organization_id = user.organization_id
        since = request.args.get('last_up_timestamp[gte]')
        until = request.args.get('last_up_timestamp[lte]')
        page = request.args.get('page')
        size = request.args.get('size')
        group_by = request.args.get('group_by')
        data_collector = request.args.getlist('data_collector[]')

        if since:
            try:
                since = dp.parse(since)
            except Exception:
                return bad_request('no valid last_up_timestamp[gte] value')

        if until:
            try:
                until = dp.parse(until)
            except Exception:
                return bad_request('no valid last_up_timestamp[lte] value')

        if since and until and since > until:
            return bad_request('since value must be before to until value')

        if page:
            try:
                page = int(page)
            except Exception:
                return bad_request('no valid page value')

        if size:
            try:
                size = int(size)
            except Exception:
                return bad_request('no valid size value')

        if group_by:
            if group_by not in ['DAY', 'HOUR']:
                return bad_request('"Group by" value is not valid')
        else:
            group_by = 'DAY'

        data_collector = get_user_collector_ids(user, data_collector)

        if group_by == 'HOUR':
            counts = StatsCounters.find(organization_id, since, until, data_collector)

            return list(map(lambda item: {'hour': "{}".format(item.hour), 'count': item.devices_count}, counts))
        else:
            counts = StatsCounters.max_devices_by_date(organization_id, since, until, data_collector)

            return list(map(lambda item: {'date': "{}".format(item.date), 'count': item.max_devices}, counts))


class AlertTypesListAPI(Resource):

    @jwt_required
    def get(self):

        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return forbidden()

        types = AlertType.find_all()

        return list(map(lambda type: type.to_json(), types))


class AlertTypesCountAPI(Resource):

    @jwt_required
    def get(self):

        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)
        resolved = request.args.get('resolved')
        risks = request.args.getlist('risk[]')
        data_collectors = request.args.getlist('data_collector[]')
        types = request.args.getlist('type[]')

        if resolved:
            resolved = resolved == 'true'

        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return forbidden()

        _from = request.args.get('from')
        to = request.args.get('to')
        organization_id = user.organization_id
        counts = AlertType.find_and_count_all(organization_id, _from, to, resolved, risks, data_collectors, types)
        types = AlertType.find_all()
        response = []

        for _type in types:
            parsed_type = _type.to_json()
            found_counts = list(filter(lambda item: item.type == _type.code, counts))

            if len(found_counts) > 0:
                parsed_type['count'] = found_counts[0].count
            else:
                parsed_type['count'] = 0
            response.append(parsed_type)

        return response


class AlertsListAPI(Resource):

    @jwt_required
    def get(self):
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return forbidden()

        organization_id = user.organization_id
        since = request.args.get('created_at[gte]')
        until = request.args.get('created_at[lte]')
        page = request.args.get('page')
        size = request.args.get('size')
        types = request.args.getlist('type[]')
        resolved = request.args.get('resolved')
        risks = request.args.getlist('risk[]')
        data_collectors = request.args.getlist('data_collector[]')
        order_by = request.args.getlist('order_by[]')
        include_parameters = request.args.get('include_parameters') == 'true'

        if since:
            try:
                since = dp.parse(since)
            except Exception:
                return bad_request('no valid created_at[gte] value')

        if until:
            try:
                until = dp.parse(until)
            except Exception:
                return bad_request('no valid created_at[lte] value')

        if since and until and since > until:
            return bad_request('since value must be before to until value')

        if not order_by or len(order_by) < 2 or order_by[1] not in ('ASC', 'DESC') or not order_by[0]:
            order_by = None

        if page:
            try:
                page = int(page)
            except Exception:
                return bad_request('no valid page value')

        if size:
            try:
                size = int(size)
            except Exception:
                return bad_request('no valid size value')

        if resolved:
            resolved = resolved == 'true'

        try:
            collectors = get_user_collector_ids(user, data_collectors)
        except ValueError as exc:
            return bad_request(str(exc))

        alerts = Alert.find(organization_id, since, until, types, resolved, risks, collectors,
                            order_by, page, size)

        if include_parameters:
            return list(map(lambda alert: alert.to_json(), alerts))
        else:
            return list(map(lambda alert: alert.to_count_json(), alerts))


class AlertsListCountAPI(Resource):

    @jwt_required
    def get(self):
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return forbidden()

        organization_id = user.organization_id
        since = request.args.get('created_at[gte]')
        until = request.args.get('created_at[lte]')
        types = request.args.getlist('type[]')
        resolved = request.args.get('resolved')
        _risks = request.args.getlist('risk[]')
        data_collectors = request.args.getlist('data_collector[]')
        group_by = request.args.get('group_by')

        if since:
            try:
                since = dp.parse(since)
            except Exception:
                return bad_request('no valid created_at[gte] value')

        if until:
            try:
                until = dp.parse(until)
            except Exception:
                return bad_request('no valid created_at[lte] value')

        if since and until and since > until:
            return bad_request('since value must be before to until value')

        if resolved:
            resolved = resolved == 'true'

        risks = ('HIGH', 'MEDIUM', 'LOW', 'INFO')
        counts_for_response = []

        data_collectors = get_user_collector_ids(user, data_collectors)

        if group_by == 'HOUR':
            if len(types) > 0 or resolved is not None or len(_risks) > 0:
                counts = Alert.count_by_hour(organization_id, since, until, types, resolved, _risks)
                counts = list(map(lambda item: {'count': item.count, 'hour': item.hour}, counts))
            else:
                counts = StatsCounters.find(organization_id, since, until, data_collectors)
                counts = list(map(lambda item: {'count': item.alerts_count, 'hour': item.hour}, counts))

            dates_with_risks = Alert.group_by_hour_and_risk(organization_id, since, until, types, resolved,
                                                            data_collectors)

            for count in counts:
                count_for_response = {'hour': "{}".format(count.get('hour')), 'count': count.get('count'), 'risk': None}

                for risk in risks:
                    filtered_hours_with_risks = list(
                        filter(lambda item: item.hour == count.get('hour') and item.risk == risk, dates_with_risks))

                    if len(filtered_hours_with_risks) > 0 and count_for_response['risk'] is None:
                        count_for_response['risk'] = risk
                counts_for_response.append(count_for_response)

        elif group_by == 'TOTAL':
            count = Alert.count(organization_id, since, until, types, resolved, _risks, data_collectors)

            return {'count': count}

        else:  # GROUP BY DAY
            if len(types) > 0 or resolved is not None or len(_risks) > 0:
                counts = Alert.count_by_date(organization_id, since, until, types, resolved, _risks)
                counts = list(map(lambda item: {'count': item.count, 'date': item.date}, counts))
            else:
                LOG.debug("stats counters day")
                counts = StatsCounters.group_by_date(organization_id, since, until, data_collectors)
                counts = list(map(lambda item: {'count': item.alerts_count, 'date': item.date}, counts))

            dates_with_risks = Alert.group_by_date_and_risk(organization_id, since, until, types, resolved,
                                                            data_collectors)

            for count in counts:
                count_for_response = {'date': "{}".format(count.get('date')), 'count': count.get('count'), 'risk': None}

                for risk in risks:
                    filtered_dates_with_risks = list(
                        filter(lambda item: item.date == count.get('date') and item.risk == risk, dates_with_risks))

                    if len(filtered_dates_with_risks) > 0 and count_for_response['risk'] is None:
                        count_for_response['risk'] = risk
                counts_for_response.append(count_for_response)

        return counts_for_response


class ResolveAlertAPI(Resource):

    @jwt_required
    def put(self, alert_id):

        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id):
            return forbidden()

        alert = Alert.find_one(alert_id)

        if alert:
            data_collector = DataCollector.find_by_id(alert.data_collector_id)

            if not data_collector:
                return internal('Not found data collector.')

            if user.organization_id != data_collector.organization_id:
                return forbidden()
        else:
            return not_found()

        comment = None

        if len(request.data) > 0:
            try:
                body = json.loads(request.data)
                comment = body.get('comment') if body is not None else None
            except Exception as exc:
                LOG.error('Error parsing body:' + str(exc))

                return bad_request('Error parsing body.')

        if comment is not None and len(comment) > 1024:
            return bad_request('Too long comment. Max length: 1024 characters.')

        alert.resolved_at = datetime.datetime.now()
        alert.resolved_by_id = user.id
        alert.resolution_comment = comment

        try:
            alert.update()

            return jsonify({"message": "Alert resolved successfully", "alert": alert.to_json()})

        except Exception as exc:
            LOG.error('There was an error updating an alert:' + str(exc))

            return internal('There was an error updating an alert.')


class PacketsListAPI(Resource):

    @jwt_required
    def get(self):

        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return forbidden()

        organization_id = user.organization_id
        since = request.args.get('date[gte]')
        until = request.args.get('date[lte]')
        page = request.args.get('page')
        size = request.args.get('size')

        if since:
            try:
                since = dp.parse(since)
            except Exception:
                return bad_request('no valid date[gte] value')

        if until:
            try:
                until = dp.parse(until)
            except Exception:
                return bad_request('no valid date[lte] value')

        if since and until and since > until:
            return bad_request('since value must be before to until value')

        if page:
            try:
                page = int(page)
            except Exception:
                return bad_request('no valid page value')
        else:
            page = 0

        if size:
            try:
                size = int(size)
            except Exception:
                return bad_request('no valid size value')
        else:
            size = 20

        packets = Packet.find(organization_id, None, since, until, page, size)

        return list(map(lambda packet: packet.to_json(), packets))


class PacketsListCountAPI(Resource):

    @jwt_required
    def get(self):

        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return forbidden()

        organization_id = user.organization_id
        since = request.args.get('date[gte]')
        until = request.args.get('date[lte]')
        group_by = request.args.get('group_by')
        data_collectors = request.args.getlist('data_collector[]')

        if since:
            try:
                since = dp.parse(since)
            except Exception:
                return bad_request('no valid date[gte] value')

        if until:
            try:
                until = dp.parse(until)
            except Exception:
                return bad_request('no valid date[lte] value')

        if since and until and since > until:
            return bad_request('since value must be before to until value')

        if group_by:
            if group_by not in ['DAY', 'HOUR']:
                return bad_request('"Group by" value is not valid')
        else:
            group_by = 'DAY'

        data_collectors = get_user_collector_ids(user, data_collectors)

        if group_by == 'HOUR':
            counts = StatsCounters.find(organization_id, since, until, data_collectors)

            return list(map(lambda item: {'hour': "{}".format(item.hour), 'count': item.packets_count}, counts))
        else:
            counts = StatsCounters.group_by_date(organization_id, since, until, data_collectors)

            return list(map(lambda item: {'date': "{}".format(item.date), 'count': item.packets_count}, counts))


class JoinRequestsListAPI(Resource):

    @jwt_required
    def get(self):

        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return forbidden()

        organization_id = user.organization_id
        since = request.args.get('date[gte]')
        until = request.args.get('date[lte]')
        page = request.args.get('page')
        size = request.args.get('size')

        if since:
            try:
                since = dp.parse(since)
            except Exception:
                return bad_request('no valid date[gte] value')

        if until:
            try:
                until = dp.parse(until)
            except Exception:
                return bad_request('no valid date[lte] value')

        if since and until and since > until:
            return bad_request('since value must be before to until value')

        if page:
            try:
                page = int(page)
            except Exception:
                return bad_request('no valid page value')
        else:
            page = 0

        if size:
            try:
                size = int(size)
            except Exception:
                return bad_request('no valid size value')
        else:
            size = 20

        join_requests = Packet.find(organization_id, 'JoinRequest', since, until, page, size)

        return list(map(lambda join_request: join_request.to_json(), join_requests))


class JoinRequestsListCountAPI(Resource):

    @jwt_required
    def get(self):

        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return forbidden()

        organization_id = user.organization_id
        since = request.args.get('date[gte]')
        until = request.args.get('date[lte]')
        group_by = request.args.get('group_by')
        data_collectors = request.args.getlist('data_collector[]')

        if since:
            try:
                since = dp.parse(since)
            except Exception:
                return bad_request('no valid date[gte] value')

        if until:
            try:
                until = dp.parse(until)
            except Exception:
                return bad_request('no valid date[lte] value')

        if since and until and since > until:
            return bad_request('since value must be before to until value')

        if group_by:
            if group_by not in ['DAY', 'HOUR']:
                return bad_request('"Group by" value is not valid')
        else:
            group_by = 'DAY'

        if group_by == 'HOUR':
            counts = StatsCounters.find(organization_id, since, until, data_collectors)

            return list(map(lambda item: {'hour': "{}".format(item.hour), 'count': item.joins_count}, counts))
        else:
            counts = StatsCounters.group_by_date(organization_id, since, until, data_collectors)

            return list(map(lambda item: {'date': "{}".format(item.date), 'count': item.joins_count}, counts))


class SESNotifications(Resource):
    def post(self):
        message_type = request.headers['x-amz-sns-message-type']
        # todo: verify authenticity of notification (compare signature in received message with signature generated from message)
        # todo: difference bounce causes
        # todo: search user mail in notification_additional_email

        if message_type == 'SubscriptionConfirmation':
            subscription_confirmation = json.loads(request.get_data())
            requests.get(url=subscription_confirmation['SubscribeURL'])
        elif message_type == 'Notification':
            # handle notifications
            notification = json.loads(request.get_data())
            message = json.loads(notification['Message'])
            maildict = message['mail']
            mails_dest = maildict['destination']

            if mails_dest:
                if message['notificationType'] == 'Delivery':  # mail was sent
                    # handle delivery notifications: do things (reset count)
                    LOG.debug("Mail sent")

                    for mail in mails_dest:
                        user_list = User.find_by_email(mail)

                        if user_list:
                            user = user_list[0]
                            send_mail_attempts = SendMailAttempts.find_by_user(user.id)

                            if send_mail_attempts:
                                send_mail_attempts.attempts = 0
                                try:
                                    send_mail_attempts.update_to_db()
                                except Exception:
                                    send_mail_attempts.rollback()
                                    LOG.error(f"Couldn\'t update the number of send mail attempts. Making a rollback")
                            else:
                                send_mail_attempts = SendMailAttempts(
                                    user_id=user.id,
                                    attempts=0,
                                )
                                try:
                                    send_mail_attempts.save_to_db()
                                except Exception:
                                    send_mail_attempts.rollback()
                                    LOG.error(f"Couldn\'t save the number of send mail attempts. Making a rollback")
                elif message['notificationType'] == 'Bounce':  # mail was bounced
                    LOG.debug('bounce')
                    # handle bounce notifications: do things (count += 1)

                    for mail in mails_dest:
                        user_list = User.find_by_email(mail)

                        if user_list:
                            user = user_list[0]
                            send_mail_attempts = SendMailAttempts.find_by_user(user.id)

                            if send_mail_attempts:
                                send_mail_attempts.attempts += 1
                                try:
                                    send_mail_attempts.update_to_db()
                                except Exception:
                                    send_mail_attempts.rollback()
                                    LOG.error(f"Couldn\'t update the number of send mail attempts. Making a rollback")

                                if send_mail_attempts.attempts >= config.SMTP_MAX_SEND_MAIL_ATTEMPTS:
                                    user.blocked = True
                                    try:
                                        user.update_to_db()
                                    except Exception:
                                        user.rollback()
                                        LOG.error(f"Couldn\'t update user data. Making a rollback")
                            else:
                                send_mail_attempts = SendMailAttempts(
                                    user_id=user.id,
                                    attempts=1,
                                )

                                try:
                                    send_mail_attempts.save_to_db()
                                except Exception:
                                    send_mail_attempts.rollback()
                                    LOG.error(f"Couldn\'t save the number of send mail attempts. Making a rollback")

        return 200


# region quarantine endpoints
class QuarantineListAPI(Resource):
    @jwt_required
    def get(self):
        # access rules? copied those of AlertsListAPI for now
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return forbidden()

        organization_id = user.organization_id
        since = request.args.get('created_at[gte]')
        until = request.args.get('created_at[lte]')
        page = request.args.get('page')
        size = request.args.get('size')
        alert_types = request.args.getlist('alerttype[]')
        devices = request.args.getlist('device[]')
        risks = request.args.getlist('risk[]')
        data_collectors = request.args.getlist('data_collector[]')
        order_by = request.args.getlist('order_by[]')

        if since:
            try:
                since = dp.parse(since)
            except Exception:
                return bad_request('no valid created_at[gte] value')

        if until:
            try:
                until = dp.parse(until)
            except Exception:
                return bad_request('no valid created_at[lte] value')

        if since and until and since > until:
            return bad_request('since value must be before or equal to until value')

        if not order_by or len(order_by) < 2 or order_by[1] not in ('ASC', 'DESC') or not order_by[0]:
            order_by = None

        if page:
            try:
                page = int(page)
            except Exception:
                return bad_request('no valid page value')

        if size:
            try:
                size = int(size)
            except Exception:
                return bad_request('no valid size value')

        recs = Quarantine.find(organization_id, since, until, alert_types, devices, risks, data_collectors, order_by,
                               page, size)

        if page and size:
            return list(map(lambda rec: rec.to_list_json(), recs.items))

        return list(map(lambda rec: rec.to_list_json(), recs))


class QuarantineListCountAPI(Resource):
    @jwt_required
    def get(self):
        # access rules? copied those of AlertsListAPI for now
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return forbidden()

        organization_id = user.organization_id

        since = request.args.get('created_at[gte]')
        until = request.args.get('created_at[lte]')
        alert_types = request.args.getlist('alerttype[]')
        devices = request.args.getlist('device[]')
        risks = request.args.getlist('risk[]')
        data_collectors = request.args.getlist('data_collector[]')
        group_by = request.args.get('group_by')

        if since:
            try:
                since = dp.parse(since)
            except Exception:
                return bad_request('no valid created_at[gte] value')

        if until:
            try:
                until = dp.parse(until)
            except Exception:
                return bad_request('no valid created_at[lte] value')

        if since and until and since > until:
            return bad_request('since value must be before or equal to until value')

        if group_by:
            if group_by == 'alert_type_name':
                counts = Quarantine.count_by_alert_type(organization_id, since, until, alert_types, devices, risks, data_collectors)

                return list(map(lambda item: {'alert_type_id': item.alert_type_id, 'alert_type_name': item.alert_type_name, 'count': item.quarantine_count}, counts))

            if group_by == 'alert_type_risk':
                counts = Quarantine.count_by_risk(organization_id, since, until, alert_types, devices, risks, data_collectors)

                return list(map(lambda item: {'alert_type_risk': item.alert_type_risk, 'count': item.quarantine_count}, counts))

            if group_by == 'data_collector_name':
                counts = Quarantine.count_by_data_collector(organization_id, since, until, alert_types, devices, risks, data_collectors)

                return list(map(lambda item: {'data_collector_id': item.data_collector_id, 'data_collector_name': item.data_collector_name, 'count': item.quarantine_count}, counts))

            return bad_request('invalid group_by parameter')

        count = Quarantine.count(organization_id, since, until, alert_types, devices, risks, data_collectors)

        return {'count': count}


class QuarantinedDevicesCountAPI(Resource):
    @jwt_required
    def get(self):
        # access rules? copied those of AlertsListAPI for now
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return forbidden()

        organization_id = user.organization_id

        since = request.args.get('created_at[gte]')
        until = request.args.get('created_at[lte]')
        alert_types = request.args.getlist('alerttype[]')
        devices = request.args.getlist('device[]')
        risks = request.args.getlist('risk[]')
        data_collectors = request.args.getlist('data_collector[]')
        group_by = request.args.get('group_by')
        order_by = request.args.getlist('order_by[]')

        if since:
            try:
                since = dp.parse(since)
            except Exception:
                return bad_request('no valid created_at[gte] value')

        if until:
            try:
                until = dp.parse(until)
            except Exception:
                return bad_request('no valid created_at[lte] value')

        if since and until and since > until:
            return bad_request('since value must be before or equal to until value')

        data_collectors = get_user_collector_ids(user, data_collectors)

        if group_by:
            if group_by == 'HOUR':
                counts = Quarantine.count_devices_by_hour(organization_id, since, until, alert_types, devices, risks, data_collectors)

                return list(map(lambda item: {'hour': "{}".format(item.hour), 'count': item.device_count}, counts))

            if group_by == 'DAY':
                counts = Quarantine.count_devices_by_date(organization_id, since, until, alert_types, devices, risks, data_collectors)

                return list(map(lambda item: {'date': "{}".format(item.date), 'count': item.device_count}, counts))

            return bad_request('"Group by" value is not valid')

        count = Quarantine.count_devices(organization_id, since, until, alert_types, devices, risks, data_collectors)

        return {'count': count}


class QuarantineRemoveManuallyAPI(Resource):
    @jwt_required
    def post(self):
        # access rules? copied those of AlertsListAPI for now
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return forbidden()
        params = json.loads(request.get_data())
        quarantine_id = params['id']
        resolution_comment = params['comment']

        alert_id = Quarantine.find_by_id(quarantine_id).alert_id
        alert = Alert.find_one(alert_id)

        alert = Alert('LAF-601',
                      device_id = alert.device_id,
                      device_session_id = alert.device_session_id,
                      gateway_id = alert.gateway_id,
                      data_collector_id = alert.data_collector_id,
                      created_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                      packet_id = alert.packet_id,
                      parameters= '{"user_id" : "%s"}'.format(user_identity),
                      show = True)
        alert.save()

        Quarantine.remove_from_quarantine_manually(quarantine_id, user.id, resolution_comment)

        return 200

# endregion
