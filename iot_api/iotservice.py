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
from iot_api import app, api, jwt
from iot_api.user_api import db
from iot_api import mail, socketio
from iot_api.user_api.model import RevokedTokenModel

import simplejson as json
from pprint import pprint
from psycopg2 import sql
import psycopg2 as postgresql

from datetime import datetime

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

@jwt.user_claims_loader
def add_claims_to_access_token(user):
    return {
        'user_roles_id': [user_role.to_json().get('user_role_id') for user_role in user.user_roles],
        'organization_id': user.organization_id
    }

@jwt.user_identity_loader 
def user_identity_lookup(user):
    return user.username

#region User & Organization
# api.add_resource(resources.UserGroupListAPI, '/api/v1.0/user_group')
api.add_resource(res.ChangeEmailAPI, '/api/v1.0/change_email/<path:token>')
api.add_resource(res.ChangeEmailRequestAPI, '/api/v1.0/change_email_request')
api.add_resource(res.ChangePasswordAPI, '/api/v1.0/change_password')
api.add_resource(res.ChangePasswordByRecoveryAPI, '/api/v1.0/change_password_by_recovery/<path:token>')
api.add_resource(res.CreatePasswordAPI, '/api/v1.0/create_password/<path:token>')
api.add_resource(res.Login, '/api/v1.0/login', )
api.add_resource(res.PasswordRecoveryAPI, '/api/v1.0/password_recovery')
api.add_resource(res.ResendActivationAPI, '/api/v1.0/resend_activation')
api.add_resource(res.Register, '/api/v1.0/register')
api.add_resource(res.TokenRefresh, '/api/v1.0/token_refresh')
api.add_resource(res.UserAPI, '/api/v1.0/user_token')
api.add_resource(res.UserCount, '/api/v1.0/user_count')
api.add_resource(res.UserInfoAPI, '/api/v1.0/user/<string:username>')
api.add_resource(res.UserListAPI, '/api/v1.0/user')
api.add_resource(res.UserLogoutAccess, '/api/v1.0/logout_access', )
api.add_resource(res.UserLogoutRefresh, '/api/v1.0/logout_refresh', )
api.add_resource(res.UserRoleListAPI, '/api/v1.0/user_roles')
#endregion

#region Data collector
api.add_resource(res.DataCollectorAPI, '/api/v1.0/data_collectors/<string:data_collector_id>')
api.add_resource(res.DataCollectorListAPI, '/api/v1.0/data_collectors')
api.add_resource(res.DataCollectorTestAPI, '/api/v1.0/data_collectors/test')
api.add_resource(res.DataCollectorsCountAPI, '/api/v1.0/data_collectors/count')
api.add_resource(res.DataCollectorActivityResource, '/api/v1.0/data_collectors/activity')
api.add_resource(res.DataCollectorTypesAPI, '/api/v1.0/data_collector_types')
#endregion

#region Devices
api.add_resource(res.DevicesListCountAPI, '/api/v1.0/devices/count')
api.add_resource(res.DevicesListAPI, '/api/v1.0/devices')
#endregion

#region Alerts
api.add_resource(res.AlertsListCountAPI, '/api/v1.0/alerts/count')
api.add_resource(res.AlertsListAPI, '/api/v1.0/alerts')
api.add_resource(res.AlertTypesListAPI, '/api/v1.0/alert_types')
api.add_resource(res.AlertTypesCountAPI, '/api/v1.0/alert_types/count')
api.add_resource(res.ResolveAlertAPI, '/api/v1.0/alerts/<string:alert_id>/resolve')
#endregion

#region Packets
api.add_resource(res.PacketsListCountAPI, '/api/v1.0/packets/count')
api.add_resource(res.PacketsListAPI, '/api/v1.0/packets')
#endregion

#region Policies
api.add_resource(res.PolicyListResource, '/api/v1.0/policies')
api.add_resource(res.PolicyResource, '/api/v1.0/policies/<int:id>')
#endregion

#region Data Collector Log Events
api.add_resource(res.DataCollectorLogEventListResource, '/api/v1.0/data_collectors/<int:data_collector_id>/log')
#endregion

#region Notifications
api.add_resource(res.NotificationPreferencesAPI, '/api/v1.0/notifications/preferences')
api.add_resource(res.NotificationEmailActivationAPI, '/api/v1.0/notifications/email_activation/<path:token>')
api.add_resource(res.NotificationPhoneActivationAPI, '/api/v1.0/notifications/phone_activation/<path:token>')
api.add_resource(res.NotificationListResource, '/api/v1.0/notifications')
api.add_resource(res.NotificationResource, '/api/v1.0/notifications/<int:id>')
api.add_resource(res.NotificationCountResource, '/api/v1.0/notifications/count')
#endregion

#region SES Notifications
api.add_resource(res.SESNotifications, '/api/v1.0/ses_notifications')
#endregion

#region Quarantine
api.add_resource(res.QuarantineListAPI, '/api/v1.0/quarantined_devices') # list of quarantine records
api.add_resource(res.QuarantineListCountAPI, '/api/v1.0/quarantined_devices/count') # count of quarantine total records (could have more than one per device)
api.add_resource(res.QuarantinedDevicesCountAPI, '/api/v1.0/quarantined_devices/devices_count') # count of quarantined devices
api.add_resource(res.QuarantineRemoveManuallyAPI, '/api/v1.0/quarantined_devices/remove') # remove devices from quarantine (mark as resolved)
#endregion

# Inventory
api.add_resource(res.AssetInformationAPI, '/api/v1.0/inventory/<asset_type>/<int:asset_id>')
api.add_resource(res.AssetAlertsAPI, '/api/v1.0/inventory/<asset_type>/<int:asset_id>/alerts')
api.add_resource(res.AssetIssuesAPI, '/api/v1.0/inventory/<asset_type>/<int:asset_id>/issues')
api.add_resource(res.AssetsListAPI, '/api/v1.0/inventory/list')
api.add_resource(res.AssetsPerVendorCountAPI, '/api/v1.0/inventory/count/vendor')
api.add_resource(res.AssetsPerGatewayCountAPI, '/api/v1.0/inventory/count/gateway')
api.add_resource(res.AssetsPerDatacollectorCountAPI, '/api/v1.0/inventory/count/data_collector')
api.add_resource(res.AssetsPerTagCountAPI, '/api/v1.0/inventory/count/tag')

# Asset importance
api.add_resource(res.AssetImportanceAPI, '/api/v1.0/inventory/set_importance')

# Tags
api.add_resource(res.TagListAPI, '/api/v1.0/tags')
api.add_resource(res.TagAPI, '/api/v1.0/tags/<int:tag_id>')
api.add_resource(res.TagAssetsAPI, '/api/v1.0/tags/<int:tag_id>/assets')

# App keys
api.add_resource(res.AppKeysAPI, '/api/v1.0/app_keys')

# Resource usage
api.add_resource(res.ResourceUsageListAPI, '/api/v1.0/resource_usage/list')
api.add_resource(res.ResourceUsagePerStatusCountAPI, '/api/v1.0/resource_usage/count/status')
api.add_resource(res.ResourceUsagePerGatewayCountAPI, '/api/v1.0/resource_usage/count/gateway')
api.add_resource(res.ResourceUsagePerSignalStrengthCountAPI, '/api/v1.0/resource_usage/count/signal')
api.add_resource(res.ResourceUsagePerPacketLossCountAPI, '/api/v1.0/resource_usage/count/loss')

if __name__ == '__main__':
    socketio.run(app, port=5000)
    db.init_app(app)