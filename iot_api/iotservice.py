# iotservice

# -*- coding: utf-8 -*-
"""
    IoT API
    ~~~~~~~~
"""

import os

from time import sleep
import iot_logging
from iot_api.user_api import resources as res
from iot_api.user_api.resources import endpoints
from iot_api import app, api, jwt
from iot_api.user_api import db
from iot_api import mail, socketio
from iot_api.user_api.resources.policy import PolicyResource, PolicyListResource
from iot_api.user_api.resources.data_collector_log_event import DataCollectorLogEventListResource
from iot_api.user_api.resources.data_collector import DataCollectorActivityResource
from iot_api.user_api.resources.notification_preferences import NotificationPreferencesResource, NotificationEmailActivationResource, NotificationPhoneActivationResource
from iot_api.user_api.resources.notification import NotificationListResource, NotificationCountResource, NotificationResource
from iot_api.user_api.model import User, Organization, Gateway, Device, RevokedTokenModel, AccountActivation, \
    PasswordReset, LoginAttempts, UserRole, UserToUserRole, ChangeEmailRequests, Alert, Packet
#from iot_api.user_api.enums import WebUrl

import simplejson as json
from pprint import pprint
from psycopg2 import sql
import psycopg2 as postgresql

from datetime import datetime
# import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from shapely.geometry import Point
from shapely.geometry.polygon import Polygon

import iot_api.user_api.websocket
import iot_api.user_api.events

basedir = os.path.abspath(os.path.dirname(__file__))

LOG = iot_logging.getLogger(__name__)


@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.close()


@app.cli.command('initdb')
def initdb_command():
    """Creates the database tables."""
    db.create_all()
    print('Initialized the database.')

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return RevokedTokenModel.is_jti_blacklisted(jti)

#region User & Organization
# api.add_resource(resources.UserGroupListAPI, '/api/v1.0/user_group')
api.add_resource(endpoints.ChangeEmailAPI, '/api/v1.0/change_email/<path:token>')
api.add_resource(endpoints.ChangeEmailRequestAPI, '/api/v1.0/change_email_request')
api.add_resource(endpoints.ChangePasswordAPI, '/api/v1.0/change_password')
api.add_resource(endpoints.ChangePasswordByRecoveryAPI, '/api/v1.0/change_password_by_recovery/<path:token>')
api.add_resource(endpoints.CreatePasswordAPI, '/api/v1.0/create_password/<path:token>')
api.add_resource(endpoints.Login, '/api/v1.0/login', )
api.add_resource(endpoints.PasswordRecoveryAPI, '/api/v1.0/password_recovery')
api.add_resource(endpoints.ResendActivationAPI, '/api/v1.0/resend_activation')
api.add_resource(endpoints.Register, '/api/v1.0/register')
api.add_resource(endpoints.TokenRefresh, '/api/v1.0/token_refresh')
api.add_resource(endpoints.UserAPI, '/api/v1.0/user_token')
api.add_resource(endpoints.UserCount, '/api/v1.0/user_count')
api.add_resource(endpoints.UserInfoAPI, '/api/v1.0/user/<string:username>')
api.add_resource(endpoints.UserListAPI, '/api/v1.0/user')
api.add_resource(endpoints.UserLogoutAccess, '/api/v1.0/logout_access', )
api.add_resource(endpoints.UserLogoutRefresh, '/api/v1.0/logout_refresh', )
api.add_resource(endpoints.UserRoleListAPI, '/api/v1.0/user_roles')
#endregion

#region Data collector
api.add_resource(endpoints.DataCollectorAPI, '/api/v1.0/data_collectors/<string:data_collector_id>')
api.add_resource(endpoints.DataCollectorListAPI, '/api/v1.0/data_collectors')
api.add_resource(endpoints.DataCollectorTestAPI, '/api/v1.0/data_collectors/test')
api.add_resource(endpoints.DataCollectorsCountAPI, '/api/v1.0/data_collectors/count')
api.add_resource(DataCollectorActivityResource, '/api/v1.0/data_collectors/activity')
api.add_resource(endpoints.DataCollectorTypesAPI, '/api/v1.0/data_collector_types')
#endregion

#region Devices
api.add_resource(endpoints.DevicesListCountAPI, '/api/v1.0/devices/count')
api.add_resource(endpoints.DevicesListAPI, '/api/v1.0/devices')
#endregion

#region Alerts
api.add_resource(endpoints.AlertsListCountAPI, '/api/v1.0/alerts/count')
api.add_resource(endpoints.AlertsListAPI, '/api/v1.0/alerts')
api.add_resource(endpoints.AlertTypesListAPI, '/api/v1.0/alert_types')
api.add_resource(endpoints.AlertTypesCountAPI, '/api/v1.0/alert_types/count')
api.add_resource(endpoints.ResolveAlertAPI, '/api/v1.0/alerts/<string:alert_id>/resolve')
#endregion

#region Packets
api.add_resource(endpoints.PacketsListCountAPI, '/api/v1.0/packets/count')
api.add_resource(endpoints.PacketsListAPI, '/api/v1.0/packets')
#endregion

#region Policies
api.add_resource(PolicyListResource, '/api/v1.0/policies')
api.add_resource(PolicyResource, '/api/v1.0/policies/<int:id>')
#endregion

#region Data Collector Log Events
api.add_resource(DataCollectorLogEventListResource, '/api/v1.0/data_collectors/<int:data_collector_id>/log')
#endregion

#region Notifications
api.add_resource(NotificationPreferencesResource, '/api/v1.0/notifications/preferences')
api.add_resource(NotificationEmailActivationResource, '/api/v1.0/notifications/email_activation/<path:token>')
api.add_resource(NotificationPhoneActivationResource, '/api/v1.0/notifications/phone_activation/<path:token>')
api.add_resource(NotificationListResource, '/api/v1.0/notifications')
api.add_resource(NotificationResource, '/api/v1.0/notifications/<int:id>')
api.add_resource(NotificationCountResource, '/api/v1.0/notifications/count')
#endregion

#region SES Notifications
api.add_resource(endpoints.SESNotifications, '/api/v1.0/ses_notifications')
#endregion

#region Quarantine
api.add_resource(endpoints.QuarantineListAPI, '/api/v1.0/quarantined_devices') # list of quarantine records
api.add_resource(endpoints.QuarantineListCountAPI, '/api/v1.0/quarantined_devices/count') # count of quarantine total records (could have more than one per device)
api.add_resource(endpoints.QuarantinedDevicesCountAPI, '/api/v1.0/quarantined_devices/devices_count') # count of quarantined devices
api.add_resource(endpoints.QuarantineRemoveManuallyAPI, '/api/v1.0/quarantined_devices/remove') # remove devices from quarantine (mark as resolved)
#endregion

# Inventory
api.add_resource(res.AssetsListAPI, '/api/v1.0/inventory/list')
api.add_resource(res.AssetsPerVendorCountAPI, '/api/v1.0/inventory/count/vendor')
api.add_resource(res.AssetsPerGatewayCountAPI, '/api/v1.0/inventory/count/gateway')
api.add_resource(res.AssetsPerDatacollectorCountAPI, '/api/v1.0/inventory/count/data_collector')
api.add_resource(res.AssetsPerTagCountAPI, '/api/v1.0/inventory/count/tag')

# Tags
api.add_resource(res.TagListAPI, '/api/v1.0/tags')
api.add_resource(res.TagAPI, '/api/v1.0/tags/<int:tag_id>')
api.add_resource(res.TagAssetsAPI, '/api/v1.0/tags/<int:tag_id>/assets')


if __name__ == '__main__':
    socketio.run(app, port=5000)
#    socketio.run(app)
    db.init_app(app)
    # app.run(debug=app.config['DEBUG'])
