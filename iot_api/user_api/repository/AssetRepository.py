import iot_logging
log = iot_logging.getLogger(__name__)

from sqlalchemy import func, or_, distinct, cast, Numeric
from sqlalchemy.sql import select, expression, text

from iot_api.user_api import db
from iot_api.user_api.repository import DeviceRepository, GatewayRepository
from iot_api.user_api.model import Device, Gateway, DataCollectorToDevice, GatewayToDevice
from iot_api.user_api.models import DataCollector, DeviceToTag, GatewayToTag, Tag
from iot_api.user_api import Error

from collections import defaultdict


def get_with(asset_id, asset_type):
    if asset_type=="device":
        asset = db.session.query(Device).\
            filter(Device.id == asset_id).\
            first()
    elif asset_type=="gateway":
        asset = db.session.query(Gateway).\
            filter(Gateway.id == asset_id).\
            first()
    else:
        raise Exception(f"Invalid asset_type: {asset_type}")
    if not asset:
        raise Exception(f"Asset with id {asset_id} and type {asset_type} not found")
    return asset


def list_all(organization_id, page=None, size=None,
             vendors=None, gateway_ids=None, data_collector_ids=None,
             tag_ids=None, asset_type=None):
    """ List assets of an organization.
    Parameters:
        - organization_id: which organization.
        - page: for pagination.
        - size: for pagination.
        - vendors[]: for filtering, lists only assets that have ANY one of these vendors.
        - gateway_ids[]: for filtering, list only the assets connected to ANY one of these gateways.
        - data_collector_ids[]: for filtering, list only the assest related to ANY of these data collectors.
        - tag_ids[]: for filtering, list only the assest that have ALL these tags.
        - asset_type: for filtering, list only this type of asset ("device" or "gateway").
    Returns:
        - A dict with the list of assets.
    """
    # Build two queries, one for devices and one for gateways
    dev_query = db.session.query(
        distinct(Device.id).label('id'),
        Device.dev_eui.label('hex_id'),
        expression.literal_column('\'Device\'').label('type'),
        Device.join_eui.label('join_eui'),
        Device.name,
        cast(expression.null(), Numeric).label('location_latitude'),
        cast(expression.null(), Numeric).label('location_longitude'),
        Device.app_name,
        DataCollector.name.label('data_collector'),
        Device.vendor,
        Device.importance
        ).select_from(Device).\
            join(DataCollectorToDevice).join(DataCollector).\
            join(GatewayToDevice).\
            filter(Device.organization_id==organization_id)
    gtw_query = db.session.query(
        distinct(Gateway.id).label('id'),
        Gateway.gw_hex_id.label('hex_id'),
        expression.literal_column('\'Gateway\'').label('type'),
        expression.null().label('join_eui'),
        Gateway.name,
        Gateway.location_latitude,
        Gateway.location_longitude,
        expression.null().label('app_name'),
        DataCollector.name.label('data_collector'),
        Gateway.vendor,
        Gateway.importance
        ).select_from(Gateway).\
            join(DataCollector).\
            filter(Gateway.organization_id == organization_id)

    # If filter parameters were given, add the respective where clauses to the queries
    if vendors:
        dev_query = dev_query.filter(Device.vendor.in_(vendors))
        gtw_query = gtw_query.filter(Gateway.vendor.in_(vendors))
    if gateway_ids:
        dev_query = dev_query.filter(GatewayToDevice.gateway_id.in_(gateway_ids))
        gtw_query = gtw_query.filter(Gateway.id.in_(gateway_ids))
    if data_collector_ids:
        dev_query = dev_query.filter(DataCollectorToDevice.data_collector_id.in_(data_collector_ids))
        gtw_query = gtw_query.filter(Gateway.data_collector_id.in_(data_collector_ids))
    if tag_ids:
        dev_query = dev_query.filter(Device.id.in_(DeviceRepository.query_ids_with(tag_ids=tag_ids)))
        gtw_query = gtw_query.filter(Gateway.id.in_(GatewayRepository.query_ids_with(tag_ids=tag_ids)))

    # Filter by device type if the parameter was given, else, make a union with queries.
    if asset_type is None:
        asset_query = dev_query.union(gtw_query)
    elif asset_type == "device":
        asset_query = dev_query
    elif asset_type == "gateway":
        asset_query = gtw_query
    else:
        raise Error.BadRequest("Invalid device type parameter")

    asset_query = asset_query.order_by(text('type desc'))
    if page and size:
        return asset_query.paginate(page=page, per_page=size, error_out=False)
    else:
        return asset_query.all()


def count_per_vendor(organization_id, vendors=None, gateway_ids=None,
                     data_collector_ids=None, tag_ids=None, asset_type=None):
    """ Count the number of assets per vendor.
    Parameters:
        - organization_id: which organization.
        - vendors[]: for filtering, lists only assets that have ANY one of these vendors.
        - gateway_ids[]: for filtering, list only the assets connected to ANY one of these gateways.
        - data_collector_ids[]: for filtering, list only the assest related to ANY of these data collectors.
        - tag_ids[]: for filtering, list only the assest that have ALL these tags.
        - asset_type: for filtering, list only this type of asset ("device" or "gateway").
    Returns:
        - List of dicts, where each dict has the vendor id and name and the count
        of assets.
    """
    # Build two queries, one for devices and one for gateways
    dev_query = db.session.query(Device.vendor, func.count(distinct(Device.id))).\
        join(DataCollectorToDevice).\
        join(GatewayToDevice).\
        group_by(Device.vendor).\
        filter(Device.organization_id==organization_id)

    gtw_query = db.session.query(Gateway.vendor, func.count(distinct(Gateway.id))).\
        group_by(Gateway.vendor).\
        filter(Gateway.organization_id==organization_id)

    # If the filtering arguments are given, add the respective where clauses to the queries
    if vendors:
        dev_query = dev_query.filter(Device.vendor.in_(vendors))
        gtw_query = gtw_query.filter(Gateway.vendor.in_(vendors))
    if gateway_ids:
        dev_query = dev_query.filter(GatewayToDevice.gateway_id.in_(gateway_ids))
        gtw_query = gtw_query.filter(Gateway.id.in_(gateway_ids))
    if data_collector_ids:
        dev_query = dev_query.filter(DataCollectorToDevice.data_collector_id.in_(data_collector_ids))
        gtw_query = gtw_query.filter(Gateway.data_collector_id.in_(data_collector_ids))
    if tag_ids:
        dev_query = dev_query.filter(Device.id.in_(DeviceRepository.query_ids_with(tag_ids=tag_ids)))
        gtw_query = gtw_query.filter(Gateway.id.in_(GatewayRepository.query_ids_with(tag_ids=tag_ids)))

    # Execute the queries, filtering by asset type
    if asset_type is None:
        all_counts = dev_query.all() + gtw_query.all()
    elif asset_type == "device":
        all_counts = dev_query.all()
    elif asset_type == "gateway":
        all_counts = gtw_query.all()
    else:
        raise Error.BadRequest("Invalid device type parameter")

    counts = defaultdict(lambda: {'name' : None, 'count' : 0})
    for e in all_counts:
        counts[e[0]]['name'] = e[0]
        counts[e[0]]['count'] += e[1]
    return [{'id' : k, 'name':v['name'], 'count':v['count']} for k, v in counts.items()]


def count_per_gateway(organization_id, vendors=None, gateway_ids=None,
                      data_collector_ids=None, tag_ids=None, asset_type=None):
    """ Count the number of assets per gateway.
    Parameters:
        - organization_id: which organization.
        - vendors[]: for filtering, lists only assets that have ANY one of these vendors.
        - gateway_ids[]: for filtering, list only the assets connected to ANY one of these gateways.
        - data_collector_ids[]: for filtering, list only the assest related to ANY of these data collectors.
        - tag_ids[]: for filtering, list only the assest that have ALL these tags.
        - asset_type: for filtering, list only this type of asset ("device" or "gateway").
    Returns:
        - List of dicts, where each dict has the gateway id and name and the count
        of assets.
    """
    # Query to count the number of devices per gateway
    dev_query = db.session.query(Gateway.id, Gateway.gw_hex_id, func.count(distinct(Device.id)).label("count")).\
        select_from(Gateway).\
        join(GatewayToDevice).\
        join(Device).\
        group_by(Gateway.id, Gateway.gw_hex_id).\
        filter(Gateway.organization_id==organization_id)

    # The number of gateway grouped by gateway is simply 1
    gtw_query = db.session.query(Gateway.id, Gateway.gw_hex_id, expression.literal_column("1").label("count")).\
        filter(Gateway.organization_id==organization_id)
    
    # If the arguments are given, filter adding the respective where clause
    if vendors:
        dev_query = dev_query.filter(Device.vendor.in_(vendors)) 
        gtw_query = gtw_query.filter(Gateway.vendor.in_(vendors)) 
    if gateway_ids:
        dev_query = dev_query.filter(Gateway.id.in_(gateway_ids))
        gtw_query = gtw_query.filter(Gateway.id.in_(gateway_ids))
    if data_collector_ids:
        dev_query = dev_query.filter(Gateway.data_collector_id.in_(data_collector_ids))
        gtw_query = gtw_query.filter(Gateway.data_collector_id.in_(data_collector_ids))
    if tag_ids:
        dev_query = dev_query.filter(Device.id.in_(DeviceRepository.query_ids_with(tag_ids=tag_ids)))
        gtw_query = gtw_query.filter(Gateway.id.in_(GatewayRepository.query_ids_with(tag_ids=tag_ids)))
    
    # Execute the queries, filtering by asset type
    if asset_type is None:
        all_counts = dev_query.all() + gtw_query.all()
    elif asset_type == "device":
        all_counts = dev_query.all()
    elif asset_type == "gateway":
        all_counts = gtw_query.all()
    else:
        raise Error.BadRequest("Invalid device type parameter")

    counts = defaultdict(lambda: {'name' : None, 'count' : 0})
    for e in all_counts:
        counts[e[0]]['name'] = e[1]
        counts[e[0]]['count'] += e[2]

    return [{'id' : k, 'name':v['name'], 'count':v['count']} for k, v in counts.items()]


def count_per_datacollector(organization_id, vendors=None, gateway_ids=None,
                            data_collector_ids=None, tag_ids=None, asset_type=None):
    """ Count the number of assets per data collector.
    Parameters:
        - organization_id: which organization.
        - vendors[]: for filtering, lists only assets that have ANY one of these vendors.
        - gateway_ids[]: for filtering, list only the assets connected to ANY one of these gateways.
        - data_collector_ids[]: for filtering, list only the assest related to ANY of these data collectors.
        - tag_ids[]: for filtering, list only the assest that have ALL these tags.
        - asset_type: for filtering, list only this type of asset ("device" or "gateway").
    Returns:
        - List of dicts, where each dict has the data_collector id and name and the count
        of assets.
    """
    # Base queries, one for devices and one for gateways
    dev_query = db.session.query(DataCollector.id, DataCollector.name, func.count(distinct(Device.id))).\
        select_from(Device).\
        join(DataCollectorToDevice).join(DataCollector).\
        join(GatewayToDevice).\
        group_by(DataCollector.id, DataCollector.name).\
        filter(DataCollector.organization_id == organization_id)

    gtw_query = db.session.query(DataCollector.id, DataCollector.name, func.count(distinct(Gateway.id))).\
        select_from(Gateway).\
        join(DataCollector).\
        group_by(DataCollector.id, DataCollector.name).\
        filter(DataCollector.organization_id==organization_id)

    # If filtering parameters are given, add the respective where clauses to the queries
    if vendors:
        dev_query = dev_query.filter(Device.vendor.in_(vendors))
        gtw_query = gtw_query.filter(Gateway.vendor.in_(vendors))
    if gateway_ids:
        dev_query = dev_query.filter(GatewayToDevice.gateway_id.in_(gateway_ids))
        gtw_query = gtw_query.filter(Gateway.id.in_(gateway_ids))
    if data_collector_ids:
        dev_query = dev_query.filter(DataCollector.id.in_(data_collector_ids))
        gtw_query = gtw_query.filter(Gateway.data_collector_id.in_(data_collector_ids))
    if tag_ids:
        dev_query = dev_query.filter(Device.id.in_(DeviceRepository.query_ids_with(tag_ids=tag_ids)))
        gtw_query = gtw_query.filter(Gateway.id.in_(GatewayRepository.query_ids_with(tag_ids=tag_ids)))

    # Execute the queries, filtering by asset type
    if asset_type is None:
        all_counts = dev_query.all() + gtw_query.all()
    elif asset_type == "device":
        all_counts = dev_query.all()
    elif asset_type == "gateway":
        all_counts = gtw_query.all()
    else:
        raise Error.BadRequest("Invalid device type parameter")
        
    # Join the results of the queries
    counts = defaultdict(lambda: {'name' : None, 'count' : 0})
    for e in all_counts:
        counts[e[0]]['name'] = e[1]
        counts[e[0]]['count'] += e[2]
    return [{'id' : k, 'name':v['name'], 'count':v['count']} for k, v in counts.items()]


def count_per_tag(organization_id, vendors=None, gateway_ids=None,
                  data_collector_ids=None, tag_ids=None, asset_type=None):
    """ Count the number of assets per tag.
    Parameters:
        - organization_id: which organization.
        - vendors[]: for filtering, lists only assets that have ANY one of these vendors.
        - gateway_ids[]: for filtering, list only the assets connected to ANY one of these gateways.
        - data_collector_ids[]: for filtering, list only the assest related to ANY of these data collectors.
        - tag_ids[]: for filtering, list only the assest that have ALL these tags.
        - asset_type: for filtering, list only this type of asset ("device" or "gateway").
    Returns:
        - List of dicts, where each dict has the tag id and name and the count
        of assets.
    """
    # Base queries, one for devices and one for gateways
    dev_query = db.session.query(Tag.id, Tag.name, func.count(distinct(Device.id))).\
        select_from(Device).\
        join(DeviceToTag).\
        join(DataCollectorToDevice).\
        join(GatewayToDevice).\
        group_by(Tag.id, Tag.name).\
        filter(Device.organization_id == organization_id)

    gtw_query = db.session.query(Tag.id, Tag.name, func.count(distinct(Gateway.id))).\
        select_from(Gateway).\
        join(GatewayToTag).\
        group_by(Tag.id, Tag.name).\
        filter(Gateway.organization_id==organization_id)

    # If filtering parameters are given, add the respective where clauses to the queries
    if vendors:
        dev_query = dev_query.filter(Device.vendor.in_(vendors))
        gtw_query = gtw_query.filter(Gateway.vendor.in_(vendors))
    if gateway_ids:
        dev_query = dev_query.filter(GatewayToDevice.gateway_id.in_(gateway_ids))
        gtw_query = gtw_query.filter(Gateway.id.in_(gateway_ids))
    if data_collector_ids:
        dev_query = dev_query.filter(DataCollectorToDevice.data_collector_id.in_(data_collector_ids))
        gtw_query = gtw_query.filter(Gateway.data_collector_id.in_(data_collector_ids))
    if tag_ids:
        dev_query = dev_query.filter(Device.id.in_(DeviceRepository.query_ids_with(tag_ids=tag_ids)))
        gtw_query = gtw_query.filter(Gateway.id.in_(GatewayRepository.query_ids_with(tag_ids=tag_ids)))

    # Execute the queries, filtering by asset type
    if asset_type is None:
        all_counts = dev_query.all() + gtw_query.all()
    elif asset_type == "device":
        all_counts = dev_query.all()
    elif asset_type == "gateway":
        all_counts = gtw_query.all()
    else:
        raise Exception("Invalid asset type parameter")

    # Join the results of the queries
    counts = defaultdict(lambda: {'name' : None, 'count' : 0})
    for e in all_counts:
        counts[e[0]]['name'] = e[1]
        counts[e[0]]['count'] += e[2]
    return [{'id' : k, 'name':v['name'], 'count':v['count']} for k, v in counts.items()]
