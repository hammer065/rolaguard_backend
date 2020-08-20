import iot_logging
log = iot_logging.getLogger(__name__)

from sqlalchemy import distinct, cast, Float
from sqlalchemy.sql import select, expression, text

from iot_api.user_api import db
from iot_api.user_api.repository import DeviceRepository, GatewayRepository
from iot_api.user_api.model import Device, Gateway, DataCollectorToDevice, GatewayToDevice
from iot_api.user_api.models import DataCollector
from iot_api.user_api import Error


def list_all(organization_id, page=None, size=None,
             gateway_ids=None, data_collector_ids=None,
             asset_type=None):
    """ List assets of an organization.
    Parameters:
        - organization_id: which organization.
        - page: for pagination.
        - size: for pagination.
        - gateway_ids[]: for filtering, list only the assets connected to ANY one of these gateways.
        - data_collector_ids[]: for filtering, list only the assest related to ANY of these data collectors.
        - asset_type: for filtering, list only this type of asset ("device" or "gateway").
    Returns:
        - A dict with the list of assets.
    """
    # Build two queries, one for devices and one for gateways
    dev_query = db.session.query(
        distinct(Device.id).label('id'),
        Device.dev_eui.label('hex_id'),
        expression.literal_column('\'Device\'').label('type'),
        Device.name,
        Device.app_name,
        DataCollector.name.label('data_collector'),
        Device.connected.label('connected'),
        Device.last_activity,
        Device.activity_freq,
        Device.npackets_up,
        Device.npackets_down,
        Device.npackets_lost.label('packet_loss'),
        Device.max_rssi
        ).select_from(Device).\
            join(DataCollectorToDevice).join(DataCollector).\
            join(GatewayToDevice).\
            filter(Device.organization_id==organization_id)
    gtw_query = db.session.query(
        distinct(Gateway.id).label('id'),
        Gateway.gw_hex_id.label('hex_id'),
        expression.literal_column('\'Gateway\'').label('type'),
        Gateway.name,
        expression.null().label('app_name'),
        DataCollector.name.label('data_collector'),
        Gateway.connected.label('connected'),
        Gateway.last_activity,
        Gateway.activity_freq,
        Gateway.npackets_up,
        Gateway.npackets_down,
        cast(expression.null(), Float).label('packet_loss'),
        cast(expression.null(), Float).label('max_rssi')
        ).select_from(Gateway).\
            join(DataCollector).\
            filter(Gateway.organization_id == organization_id)
    #TODO: add number of devices per gateway / number of gateways per device
    #TODO: add number of sessions (distinct devAddr)

    # If filter parameters were given, add the respective where clauses to the queries
    if gateway_ids:
        dev_query = dev_query.filter(GatewayToDevice.gateway_id.in_(gateway_ids))
        gtw_query = gtw_query.filter(Gateway.id.in_(gateway_ids))
    if data_collector_ids:
        dev_query = dev_query.filter(DataCollectorToDevice.data_collector_id.in_(data_collector_ids))
        gtw_query = gtw_query.filter(Gateway.data_collector_id.in_(data_collector_ids))

    # Filter by device type if the parameter was given, else, make a union with queries.
    if asset_type is None:
        asset_query = dev_query.union(gtw_query)
    elif asset_type == "device":
        asset_query = dev_query
    elif asset_type == "gateway":
        asset_query = gtw_query
    else:
        raise Error.BadRequest("Invalid device type parameter")

    #TODO: add filter by dates

    asset_query = asset_query.order_by(text('type desc, connected desc, id'))
    if page and size:
        return asset_query.paginate(page=page, per_page=size, error_out=False)
    else:
        return asset_query.all()