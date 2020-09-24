from iot_api.user_api import db
from iot_api.user_api import Error
from iot_api.user_api.model import GatewayToDevice

def find_all_with(gateway_id=None, device_id=None): 
    if (not gateway_id and not device_id):
        raise Error.BadRequest("Either device or gateway id is required")
    query = db.session.query(GatewayToDevice)
    if gateway_id:
        query = query.filter(GatewayToDevice.gateway_id == gateway_id)
    if device_id:
        query = query.filter(GatewayToDevice.device_id == device_id)
    return query.all()