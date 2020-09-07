import iot_logging
log = iot_logging.getLogger(__name__)

from sqlalchemy import distinct, cast, Float, func, null
from sqlalchemy.sql import select, expression, text, not_, and_

from iot_api.user_api import db
from iot_api.user_api.repository import DeviceRepository, GatewayRepository
from iot_api.user_api.model import Device, Gateway, GatewayToDevice
from iot_api.user_api.models import DataCollector
from iot_api.user_api import Error

from collections import defaultdict

def get_with(asset_id, asset_type, organization_id=None):
    """ Gets an asset from database
    Request parameters:
        - asset_id: database id of the asset
        - asset_type: type of the requested asset, can be "device" or "gateway".
        - organization_id (optional): when given, asserts that received organization
            matchs the asset's organization
    Returns:
        - Model object of requested asset
    """
    if asset_type=="device":
        asset = db.session.query(
            Device.id,
            Device.organization_id,
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
            Device.max_rssi,
            Device.max_lsnr,
            Device.ngateways_connected_to,
            Device.payload_size
            ).join(DataCollector).\
                join(GatewayToDevice).\
                filter(Device.id == asset_id).\
                first()
    elif asset_type=="gateway":
        asset = db.session.query(
            Gateway.id,
            Gateway.organization_id,
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
            cast(expression.null(), Float).label('max_rssi'),
            cast(expression.null(), Float).label('max_lsnr'),
            cast(expression.null(), Float).label('ngateways_connected_to'),
            cast(expression.null(), Float).label('payload_size')
            ).join(DataCollector).\
                filter(Gateway.id == asset_id).\
                first()
    else:
        raise Error.BadRequest(f"Invalid asset_type: {asset_type}. Valid values are \'device\' or \'gateway\'")
    if not asset:
        raise Error.NotFound(f"Asset with id {asset_id} and type {asset_type} not found")
    if organization_id and asset.organization_id != organization_id:
        raise Error.Forbidden("User's organization's different from asset organization")
    return asset

def list_all(organization_id, page=None, size=None,
            asset_type=None, asset_status=None, gateway_ids=None,
            min_signal_strength=None, max_signal_strength=None,
            min_packet_loss=None, max_packet_loss=None):
    """ List assets of an organization and their resource usage information.
    Parameters: 
        - asset_type: for filtering, count only this type of asset ("device" or "gateway").
        - asset_status: for filtering, count only assets with this status ("connected" or "disconnected").
        - gateway_ids[]: for filtering, count only the assets connected to ANY one of these gateways.
        - min_signal_strength: for filtering, count only the assets with signal strength not lower than this value (dBm)
        - max_signal_strength: for filtering, count only the assets with signal strength not higher than this value (dBm)
        - min_packet_loss: for filtering, count only the assets with packet loss not lower than this value (percentage)
        - max_packet_loss: for filtering, count only the assets with packet loss not higher than this value (percentage)
    Returns:
        - Dict with the list of assets.
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
        Device.max_rssi,
        Device.max_lsnr,
        Device.payload_size,
        Device.ngateways_connected_to
        ).select_from(Device).\
            join(DataCollector).\
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
        cast(expression.null(), Float).label('max_rssi'),
        cast(expression.null(), Float).label('max_lsnr'),
        cast(expression.null(), Float).label('payload_size'),
        cast(expression.null(), Float).label('ngateways_connected_to')
        ).select_from(Gateway).\
            join(DataCollector).\
            filter(Gateway.organization_id == organization_id)
    #TODO: add number of devices per gateway / number of gateways per device
    #TODO: add number of sessions (distinct devAddr)

    queries = add_filters(
        dev_query = dev_query,
        gtw_query = gtw_query,
        asset_type = asset_type,
        asset_status = asset_status,
        gateway_ids = gateway_ids,
        min_signal_strength = min_signal_strength,
        max_signal_strength = max_signal_strength,
        min_packet_loss = min_packet_loss,
        max_packet_loss = max_packet_loss)    
    dev_query = queries[0]
    gtw_query = queries[1]

    # Filter by device type if the parameter was given, else, make a union with queries.
    if asset_type is None:
        asset_query = dev_query.union(gtw_query)
    elif asset_type == "device":
        asset_query = dev_query
    elif asset_type == "gateway":
        asset_query = gtw_query
    else:
        raise Error.BadRequest("Invalid asset type parameter")

    asset_query = asset_query.order_by(text('type desc, connected desc, id'))
    if page and size:
        return asset_query.paginate(page=page, per_page=size, error_out=False)
    else:
        return asset_query.all()

def count_per_status(organization_id, asset_type=None, asset_status=None, gateway_ids=None,
                    min_signal_strength=None, max_signal_strength=None,
                    min_packet_loss=None, max_packet_loss=None):
    """ Count assets (devices+gateways) grouped by status (connected/disconnected).
    Parameters: 
        - asset_type: for filtering, count only this type of asset ("device" or "gateway").
        - asset_status: for filtering, count only assets with this status ("connected" or "disconnected").
        - gateway_ids[]: for filtering, count only the assets connected to ANY one of these gateways.
        - min_signal_strength: for filtering, count only the assets with signal strength not lower than this value (dBm)
        - max_signal_strength: for filtering, count only the assets with signal strength not higher than this value (dBm)
        - min_packet_loss: for filtering, count only the assets with packet loss not lower than this value (percentage)
        - max_packet_loss: for filtering, count only the assets with packet loss not higher than this value (percentage)
    Returns:
        - List of dicts, where each dict has the status id and name, and the count of assets (id = name = 'connected'/'disconnected')
    """
    dev_query = db.session.query(Device.connected, func.count(distinct(Device.id)).label("count_result")).\
        select_from(Device).\
        join(GatewayToDevice).\
        group_by(Device.connected).\
        filter(Device.organization_id==organization_id)

    gtw_query = db.session.query(Gateway.connected, func.count(distinct(Gateway.id)).label("count_result")).\
        select_from(Gateway).\
        group_by(Gateway.connected).\
        filter(Gateway.organization_id==organization_id)

    queries = add_filters(
        dev_query = dev_query,
        gtw_query = gtw_query,
        asset_type = asset_type,
        asset_status = asset_status,
        gateway_ids = gateway_ids,
        min_signal_strength = min_signal_strength,
        max_signal_strength = max_signal_strength,
        min_packet_loss = min_packet_loss,
        max_packet_loss = max_packet_loss)    
    dev_query = queries[0]
    gtw_query = queries[1]
    
    result = query_for_count(dev_query = dev_query, gtw_query = gtw_query, asset_type = asset_type)

    # Join the results of the queries
    counts = {
        'connected': {
            'name': 'connected',
            'count': 0
        },
        'disconnected': {
            'name': 'disconnected',
            'count': 0
        }
    }
    for row in result:
        if row.connected:
            status = 'connected'
        else:
            status = 'disconnected'
        counts[status]['count'] += row.count_result

    return [{'id' : k, 'name':v['name'], 'count':v['count']} for k, v in counts.items()]

def count_per_gateway(organization_id, asset_type=None, asset_status=None, gateway_ids=None,
                    min_signal_strength=None, max_signal_strength=None,
                    min_packet_loss=None, max_packet_loss=None):
    """ Count assets (devices+gateways) grouped by gateway.
    Parameters: 
        - asset_type: for filtering, count only this type of asset ("device" or "gateway").
        - asset_status: for filtering, count only assets with this status ("connected" or "disconnected").
        - gateway_ids[]: for filtering, count only the assets connected to ANY one of these gateways.
        - min_signal_strength: for filtering, count only the assets with signal strength not lower than this value (dBm)
        - max_signal_strength: for filtering, count only the assets with signal strength not higher than this value (dBm)
        - min_packet_loss: for filtering, count only the assets with packet loss not lower than this value (percentage)
        - max_packet_loss: for filtering, count only the assets with packet loss not higher than this value (percentage)
    Returns:
        - List of dicts, where each dict has the gateway id and name, and the count of assets (name = hex_id)
    """
    # Query to count the number of devices per gateway
    dev_query = db.session.query(Gateway.id, Gateway.gw_hex_id, func.count(distinct(Device.id)).label("count_result")).\
        select_from(Gateway).\
        join(GatewayToDevice).\
        join(Device).\
        group_by(Gateway.id, Gateway.gw_hex_id).\
        filter(Gateway.organization_id==organization_id)

    # The number of gateway grouped by gateway is simply 1
    gtw_query = db.session.query(Gateway.id, Gateway.gw_hex_id, expression.literal_column("1").label("count_result")).\
        filter(Gateway.organization_id==organization_id)

    queries = add_filters(
        dev_query = dev_query,
        gtw_query = gtw_query,
        asset_type = asset_type,
        asset_status = asset_status,
        gateway_ids = gateway_ids,
        min_signal_strength = min_signal_strength,
        max_signal_strength = max_signal_strength,
        min_packet_loss = min_packet_loss,
        max_packet_loss = max_packet_loss)    
    dev_query = queries[0]
    gtw_query = queries[1]
    
    result = query_for_count(dev_query = dev_query, gtw_query = gtw_query, asset_type = asset_type)

    counts = defaultdict(lambda: {'name' : None, 'count' : 0})
    for row in result:
        counts[row.id]['name'] = row.gw_hex_id
        counts[row.id]['count'] += row.count_result

    return [{'id' : k, 'name':v['name'], 'count':v['count']} for k, v in counts.items()]

def count_per_signal_strength(organization_id, asset_type=None, asset_status=None, gateway_ids=None,
                    min_signal_strength=None, max_signal_strength=None,
                    min_packet_loss=None, max_packet_loss=None):
    """ Count assets (devices+gateways) grouped by specific ranges of signal strength values
    Parameters: 
        - asset_type: for filtering, count only this type of asset ("device" or "gateway").
        - asset_status: for filtering, count only assets with this status ("connected" or "disconnected").
        - gateway_ids[]: for filtering, count only the assets connected to ANY one of these gateways.
        - min_signal_strength: for filtering, count only the assets with signal strength not lower than this value (dBm)
        - max_signal_strength: for filtering, count only the assets with signal strength not higher than this value (dBm)
        - min_packet_loss: for filtering, count only the assets with packet loss not lower than this value (percentage)
        - max_packet_loss: for filtering, count only the assets with packet loss not higher than this value (percentage)
    Returns:
        - List of dicts, where each dict has the signal strength range id and name, and the count of assets
    """

    # For every 0 <= i <= 5, range_names[i] includes signal strength values in the range [L,R) = [range_limits[i], range_limits[i+1])
    range_limits = [-10000, -120, -110, -100, -75, -50, 1]
    range_names = ['Unusable', 'Very weak', 'Weak', 'Okay', 'Great', 'Excellent']
    dev_query = db.session.query()
    gtw_query = db.session.query()
    for i in range(0, len(range_names)):
        name = range_names[i]
        L = range_limits[i]
        R = range_limits[i+1]
        dev_query = dev_query.add_column(func.count(distinct(Device.id)).filter(and_(
            Device.max_rssi != null(),
            L <= Device.max_rssi,
            Device.max_rssi < R
            )).label(name))
        
        # Gateways are not considered because they don't have the rssi value
        gtw_query = gtw_query.add_column(expression.literal_column("0").label(name))

    dev_query = dev_query.\
        select_from(Device).\
        join(GatewayToDevice).\
        filter(Device.organization_id==organization_id)

    queries = add_filters(
        dev_query = dev_query,
        gtw_query = gtw_query,
        asset_type = asset_type,
        asset_status = asset_status,
        gateway_ids = gateway_ids,
        min_signal_strength = min_signal_strength,
        max_signal_strength = max_signal_strength,
        min_packet_loss = min_packet_loss,
        max_packet_loss = max_packet_loss)    
    dev_query = queries[0]
    gtw_query = queries[1]
    
    result = query_for_count(dev_query = dev_query, gtw_query = gtw_query, asset_type = asset_type)

    counts = defaultdict(lambda: {'name' : None, 'count' : 0})
    for row in result:
        if len(row) != len(range_names):
            log.error(f"Length of range_names and length of row in signal strength query result don't match ({len(range_names)}, {len(row)})")
            raise Exception()
        for i in range(0, len(row)):
            name = range_names[i]
            L = range_limits[i]
            R = range_limits[i+1]
            counts[(L,R)]['name'] = name
            counts[(L,R)]['count'] += row[i]

    return [{'id' : k, 'name':v['name'], 'count':v['count']} for k, v in counts.items()]

def count_per_packet_loss(organization_id, asset_type=None, asset_status=None, gateway_ids=None,
                    min_signal_strength=None, max_signal_strength=None,
                    min_packet_loss=None, max_packet_loss=None):
    """ Count assets (devices+gateways) grouped by specific ranges of packet loss values
    Parameters: 
        - asset_type: for filtering, count only this type of asset ("device" or "gateway").
        - asset_status: for filtering, count only assets with this status ("connected" or "disconnected").
        - gateway_ids[]: for filtering, count only the assets connected to ANY one of these gateways.
        - min_signal_strength: for filtering, count only the assets with signal strength not lower than this value (dBm)
        - max_signal_strength: for filtering, count only the assets with signal strength not higher than this value (dBm)
        - min_packet_loss: for filtering, count only the assets with packet loss not lower than this value (percentage)
        - max_packet_loss: for filtering, count only the assets with packet loss not higher than this value (percentage)
    Returns:
        - List of dicts, where each dict has the packet loss range id and name, and the count of assets
    """

    # The packet loss ranges are defined as [L,R) = [range_limits[i], range_limits[i+1]) for every 0 <= i <= 9
    range_limits = [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 101]
    range_names = ['[0,10)', '[10,20)', '[20,30)', '[30,40)', '[40,50)', '[50,60)', '[60,70)', '[70,80)', '[80,90)', '[90,100]']
    dev_query = db.session.query()
    gtw_query = db.session.query()
    for i in range(0, len(range_names)):
        name = range_names[i]
        L = range_limits[i]
        R = range_limits[i+1]
        dev_query = dev_query.add_column(func.count(distinct(Device.id)).filter(and_(
            Device.npackets_lost != null(),
            Device.npackets_up + Device.npackets_down > 0,
            L <= 100*Device.npackets_up*Device.npackets_lost \
                /(Device.npackets_up*(1+Device.npackets_lost) + Device.npackets_down),
            R > 100*Device.npackets_up*Device.npackets_lost \
                /(Device.npackets_up*(1+Device.npackets_lost) + Device.npackets_down)
            )).label(name))
        
        # Gateways are not considered because they don't have the loss value
        gtw_query = gtw_query.add_column(expression.literal_column("0").label(name))

    dev_query = dev_query.\
        select_from(Device).\
        join(GatewayToDevice).\
        filter(Device.organization_id==organization_id)

    queries = add_filters(
        dev_query = dev_query,
        gtw_query = gtw_query,
        asset_type = asset_type,
        asset_status = asset_status,
        gateway_ids = gateway_ids,
        min_signal_strength = min_signal_strength,
        max_signal_strength = max_signal_strength,
        min_packet_loss = min_packet_loss,
        max_packet_loss = max_packet_loss)    
    dev_query = queries[0]
    gtw_query = queries[1]
    
    result = query_for_count(dev_query = dev_query, gtw_query = gtw_query, asset_type = asset_type)

    counts = defaultdict(lambda: {'name' : None, 'count' : 0})
    for row in result:
        if len(row) != len(range_names):
            log.error(f"Length of range_names and length of row in packet loss query result don't match ({len(range_names)}, {len(row)})")
            raise Exception()
        for i in range(0, len(row)):
            name = range_names[i]
            L = range_limits[i]
            R = range_limits[i+1]
            counts[(L,R)]['name'] = name
            counts[(L,R)]['count'] += row[i]

    return [{'id' : k, 'name':v['name'], 'count':v['count']} for k, v in counts.items()]
    
def add_filters(dev_query, gtw_query, asset_type=None, asset_status=None, 
                gateway_ids=None, min_signal_strength=None, max_signal_strength=None,
                min_packet_loss=None, max_packet_loss=None):
    """
    Helper function to add the filters to dev_query and gtw_query.
    Returns the tuple (dev_query, gtw_query) with the corresponding filters added.
    """
    if asset_status == 'connected':
        dev_query = dev_query.filter(Device.connected)
        gtw_query = gtw_query.filter(Gateway.connected)
    elif asset_status == 'disconnected':
        dev_query = dev_query.filter(not_(Device.connected))
        gtw_query = gtw_query.filter(not_(Gateway.connected))
    elif asset_status is not None:
        raise Error.BadRequest("Invalid asset status parameter")
    if gateway_ids:
        dev_query = dev_query.filter(GatewayToDevice.gateway_id.in_(gateway_ids))
        gtw_query = gtw_query.filter(Gateway.id.in_(gateway_ids))
    if min_signal_strength is not None:
        dev_query = dev_query.filter(and_(Device.max_rssi != null(), Device.max_rssi >= min_signal_strength))
    if max_signal_strength is not None:
        dev_query = dev_query.filter(and_(Device.max_rssi != null(), Device.max_rssi < max_signal_strength))
    if min_packet_loss is not None:
        dev_query = dev_query.filter(and_(
            Device.npackets_up + Device.npackets_down > 0,
            Device.npackets_lost != null(),
            100*Device.npackets_up*Device.npackets_lost \
                /(Device.npackets_up*(1+Device.npackets_lost) + Device.npackets_down) \
                    >= min_packet_loss
        ))
    if max_packet_loss is not None:
        dev_query = dev_query.filter(and_(
            Device.npackets_up + Device.npackets_down > 0,
            Device.npackets_lost != null(),
            100*Device.npackets_up*Device.npackets_lost \
                /(Device.npackets_up*(1+Device.npackets_lost) + Device.npackets_down) \
                    < max_packet_loss
        ))

    return (dev_query, gtw_query)

def query_for_count(dev_query, gtw_query, asset_type):
    """
    Helper function to execute the queries for
    count methods, filtering by asset type
    """
    if asset_type is None:
        result = dev_query.all() + gtw_query.all()
    elif asset_type == "device":
        result = dev_query.all()
    elif asset_type == "gateway":
        result = gtw_query.all()
    else:
        raise Error.BadRequest("Invalid asset type parameter")
    return result