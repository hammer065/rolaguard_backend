from iot_api.user_api.resources.endpoints import *
from iot_api.user_api.resources.Inventory import (AssetsListAPI,
    AssetsPerVendorCountAPI, AssetsPerGatewayCountAPI,
    AssetsPerDatacollectorCountAPI, AssetsPerTagCountAPI)
from iot_api.user_api.resources.Tag import (TagAPI, TagListAPI, TagAssetsAPI)
from iot_api.user_api.resources.NotificationPreferences import (
    NotificationPreferencesAPI, 
    NotificationEmailActivationAPI,
    NotificationPhoneActivationAPI
    )
from iot_api.user_api.resources.AssetImportance import AssetImportanceAPI
