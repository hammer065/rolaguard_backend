import iot_logging
log = iot_logging.getLogger(__name__)

from sqlalchemy import distinct, cast, Float, func, null, case, BigInteger
from sqlalchemy.sql import select, expression, text, not_, and_

from iot_api.user_api import db
from iot_api.user_api.repository import DeviceRepository, GatewayRepository
from iot_api.user_api.model import Device, Gateway, GatewayToDevice, DeviceSession, Packet
from iot_api.user_api.models import DataCollector, Policy, PolicyItem, CounterType, DeviceCounters, GatewayCounters, RowProcessed
from iot_api.user_api import Error

from collections import defaultdict

dev_wanted_counters = [CounterType.PACKETS_UP, CounterType.PACKETS_DOWN, CounterType.PACKETS_LOST, 
        CounterType.RETRANSMISSIONS, CounterType.JOIN_REQUESTS, CounterType.FAILED_JOIN_REQUESTS]
gtw_wanted_counters = [CounterType.PACKETS_UP, CounterType.PACKETS_DOWN]

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
        asset_query = db.session.query(
            Device.id,
            Device.organization_id,
            Device.dev_eui.label('hex_id'),
            expression.literal_column('\'Device\'').label('type'),
            Device.name,
            Device.app_name,
            DataCollector.name.label('data_collector'),
            PolicyItem.parameters.label('policy_parameters'),
            Device.connected.label('connected'),
            Device.last_activity,
            Device.activity_freq,
            Device.activity_freq_variance,
            Device.npackets_up,
            Device.npackets_down,
            Device.npackets_lost.label('packet_loss'),
            Device.max_rssi,
            Device.max_lsnr,
            Device.ngateways_connected_to,
            Device.payload_size,
            Device.last_packets_list
            ).filter(Device.id == asset_id).\
                join(DataCollector, Device.data_collector_id == DataCollector.id).\
                join(Policy, Policy.id == DataCollector.policy_id).\
                join(PolicyItem, and_(Policy.id == PolicyItem.policy_id, PolicyItem.alert_type_code == 'LAF-401')).\
                join(RowProcessed, RowProcessed.analyzer == 'packet_analyzer').\
                join(Packet, Packet.id == RowProcessed.last_row).\
                join(DeviceCounters, and_(
                    DeviceCounters.device_id == Device.id, 
                    DeviceCounters.counter_type.in_(dev_wanted_counters),
                    DeviceCounters.last_update + func.make_interval(0,0,0,1) > Packet.date
                    ), isouter=True).\
                group_by(Device.id, DataCollector.name, PolicyItem.parameters)

        asset_query = add_counters_columns(asset_query, dev_wanted_counters, DeviceCounters)
        asset = asset_query.first()

    elif asset_type=="gateway":
        asset_query = db.session.query(
            Gateway.id,
            Gateway.organization_id,
            Gateway.gw_hex_id.label('hex_id'),
            expression.literal_column('\'Gateway\'').label('type'),
            Gateway.name,
            expression.null().label('app_name'),
            DataCollector.name.label('data_collector'),
            expression.null().label('policy_parameters'),
            Gateway.connected.label('connected'),
            Gateway.last_activity,
            Gateway.activity_freq,
            cast(expression.null(), Float).label('activity_freq_variance'),
            Gateway.npackets_up,
            Gateway.npackets_down,
            cast(expression.null(), Float).label('packet_loss'),
            cast(expression.null(), Float).label('max_rssi'),
            cast(expression.null(), Float).label('max_lsnr'),
            cast(expression.null(), Float).label('ngateways_connected_to'),
            cast(expression.null(), Float).label('payload_size'),
            expression.null().label('last_packets_list')
            ).filter(Gateway.id == asset_id).\
                join(DataCollector, Gateway.data_collector_id == DataCollector.id).\
                join(RowProcessed, RowProcessed.analyzer == 'packet_analyzer').\
                join(Packet, Packet.id == RowProcessed.last_row).\
                join(GatewayCounters, and_(
                    GatewayCounters.gateway_id == Gateway.id, 
                    GatewayCounters.counter_type.in_(gtw_wanted_counters),
                    GatewayCounters.last_update + func.make_interval(0,0,0,1) > Packet.date
                    ), isouter=True).\
                group_by(Gateway.id, DataCollector.name)

        asset_query = add_counters_columns(asset_query, gtw_wanted_counters, GatewayCounters)
        asset = asset_query.first()
    else:
        raise Error.BadRequest(f"Invalid asset_type: {asset_type}. Valid values are \'device\' or \'gateway\'")
    if not asset:
        raise Error.NotFound(f"Asset with id {asset_id} and type {asset_type} not found")
    if organization_id and asset.organization_id != organization_id:
        raise Error.Forbidden("User's organization's different from asset organization")
    return asset

def list_all(organization_id, page=None, size=None,
            asset_type=None, asset_status=None, 
            gateway_ids=None, device_ids= None,
            min_signal_strength=None, max_signal_strength=None,
            min_packet_loss=None, max_packet_loss=None):
    """ List assets of an organization and their resource usage information.
    Parameters: 
        - asset_type: for filtering, count only this type of asset ("device" or "gateway").
        - asset_status: for filtering, count only assets with this status ("connected" or "disconnected").
        - gateway_ids[]: for filtering, count only the assets connected to ANY one of these gateways.
        - device_ids[]: for filtering, list only the assets related to ANY of these devices
        - min_signal_strength: for filtering, count only the assets with signal strength not lower than this value (dBm)
        - max_signal_strength: for filtering, count only the assets with signal strength not higher than this value (dBm)
        - min_packet_loss: for filtering, count only the assets with packet loss not lower than this value (percentage)
        - max_packet_loss: for filtering, count only the assets with packet loss not higher than this value (percentage)
    Returns:
        - Dict with the list of assets.
    """
    last_dev_addrs = db.session.\
        query(DeviceSession.device_id, func.max(DeviceSession.last_activity).label('last_activity')).\
        group_by(DeviceSession.device_id).\
        subquery()

    # Build two queries, one for devices and one for gateways
    dev_query = db.session.query(
        Device.id.label('id'),
        Device.dev_eui.label('hex_id'),
        DeviceSession.dev_addr.label('dev_addr'),
        expression.literal_column('\'Device\'').label('type'),
        Device.name,
        Device.app_name,
        DataCollector.name.label('data_collector'),
        PolicyItem.parameters.label('policy_parameters'),
        Device.connected.label('connected'),
        Device.last_activity,
        Device.activity_freq,
        Device.activity_freq_variance,
        Device.npackets_up,
        Device.npackets_down,
        Device.npackets_lost.label('packet_loss'),
        Device.max_rssi,
        Device.max_lsnr,
        Device.payload_size,
        Device.ngateways_connected_to
        ).select_from(Device).\
            filter(Device.organization_id==organization_id).\
            filter(Device.pending_first_connection==False).\
            join(DataCollector, Device.data_collector_id == DataCollector.id).\
            join(Policy, Policy.id == DataCollector.policy_id).\
            join(PolicyItem, and_(Policy.id == PolicyItem.policy_id, PolicyItem.alert_type_code == 'LAF-401')).\
            join(last_dev_addrs, Device.id == last_dev_addrs.c.device_id).\
            join(DeviceSession, and_(DeviceSession.device_id == Device.id, DeviceSession.last_activity == last_dev_addrs.c.last_activity)).\
            join(RowProcessed, RowProcessed.analyzer == 'packet_analyzer').\
            join(Packet, Packet.id == RowProcessed.last_row).\
            join(DeviceCounters, and_(
                DeviceCounters.device_id == Device.id, 
                DeviceCounters.counter_type.in_(dev_wanted_counters),
                DeviceCounters.last_update + func.make_interval(0,0,0,1) > Packet.date
                ), isouter=True).\
            group_by(Device.id, DeviceSession.dev_addr, DataCollector.name, PolicyItem.parameters)

    gtw_query = db.session.query(
        distinct(Gateway.id).label('id'),
        Gateway.gw_hex_id.label('hex_id'),
        expression.null().label('dev_addr'),
        expression.literal_column('\'Gateway\'').label('type'),
        Gateway.name,
        expression.null().label('app_name'),
        DataCollector.name.label('data_collector'),
        expression.null().label('policy_parameters'),
        Gateway.connected.label('connected'),
        Gateway.last_activity,
        Gateway.activity_freq,
        cast(expression.null(), Float).label('activity_freq_variance'),
        Gateway.npackets_up,
        Gateway.npackets_down,
        cast(expression.null(), Float).label('packet_loss'),
        cast(expression.null(), Float).label('max_rssi'),
        cast(expression.null(), Float).label('max_lsnr'),
        cast(expression.null(), Float).label('payload_size'),
        cast(expression.null(), Float).label('ngateways_connected_to')
        ).select_from(Gateway).\
            filter(Gateway.organization_id == organization_id).\
            join(DataCollector, Gateway.data_collector_id == DataCollector.id).\
            join(RowProcessed, RowProcessed.analyzer == 'packet_analyzer').\
            join(Packet, Packet.id == RowProcessed.last_row).\
            join(GatewayCounters, and_(
                GatewayCounters.gateway_id == Gateway.id, 
                GatewayCounters.counter_type.in_(gtw_wanted_counters),
                GatewayCounters.last_update + func.make_interval(0,0,0,1) > Packet.date
                ), isouter=True).\
            group_by(Gateway.id, DataCollector.name)

    # Add a column for every counter type to each query, using the wanted_counters lists
    dev_query = add_counters_columns(dev_query, dev_wanted_counters, DeviceCounters)
    gtw_query = add_counters_columns(gtw_query, gtw_wanted_counters, GatewayCounters)

    queries = add_filters(
        dev_query = dev_query,
        gtw_query = gtw_query,
        asset_type = asset_type,
        asset_status = asset_status,
        gateway_ids = gateway_ids,
        device_ids = device_ids,
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

def count_per_status(organization_id, asset_type=None, asset_status=None,
                    gateway_ids=None, device_ids=None,
                    min_signal_strength=None, max_signal_strength=None,
                    min_packet_loss=None, max_packet_loss=None):
    """ Count assets (devices+gateways) grouped by status (connected/disconnected).
    Parameters: 
        - asset_type: for filtering, count only this type of asset ("device", "gateway" or "none" for no assets).
        - asset_status: for filtering, count only assets with this status ("connected" or "disconnected").
        - gateway_ids[]: for filtering, count only the assets connected to ANY one of these gateways.
        - device_ids[]: for filtering, list only the assets related to ANY of these devices
        - min_signal_strength: for filtering, count only the assets with signal strength not lower than this value (dBm)
        - max_signal_strength: for filtering, count only the assets with signal strength not higher than this value (dBm)
        - min_packet_loss: for filtering, count only the assets with packet loss not lower than this value (percentage)
        - max_packet_loss: for filtering, count only the assets with packet loss not higher than this value (percentage)
    Returns:
        - List of dicts, where each dict has the status id and name, and the count of assets (id = name = 'connected'/'disconnected')
    """
    dev_query = db.session.query(Device.connected, func.count(distinct(Device.id)).label("count_result")).\
        select_from(Device).\
        group_by(Device.connected).\
        filter(Device.organization_id==organization_id).\
        filter(Device.pending_first_connection==False)

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
        device_ids = device_ids,
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

    if asset_type is not 'none':
        for row in result:
            if row.connected:
                status = 'connected'
            else:
                status = 'disconnected'
            counts[status]['count'] += row.count_result

    return [{'id' : k, 'name':v['name'], 'count':v['count']} for k, v in counts.items()]

def count_per_gateway(organization_id, asset_type=None, asset_status=None,
                    gateway_ids=None, device_ids=None,
                    min_signal_strength=None, max_signal_strength=None,
                    min_packet_loss=None, max_packet_loss=None):
    """ Count assets (devices+gateways) grouped by gateway.
    Parameters: 
        - asset_type: for filtering, count only this type of asset ("device", "gateway" or "none" for no assets).
        - asset_status: for filtering, count only assets with this status ("connected" or "disconnected").
        - gateway_ids[]: for filtering, count only the assets connected to ANY one of these gateways.
        - device_ids[]: for filtering, list only the assets related to ANY of these devices
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
        join(GatewayToDevice, GatewayToDevice.gateway_id == Gateway.id).\
        join(Device, Device.id == GatewayToDevice.device_id).\
        group_by(Gateway.id, Gateway.gw_hex_id).\
        filter(Gateway.organization_id==organization_id).\
        filter(Device.pending_first_connection==False)

    # The number of gateway grouped by gateway is simply 1
    gtw_query = db.session.query(Gateway.id, Gateway.gw_hex_id, expression.literal_column("1").label("count_result")).\
        filter(Gateway.organization_id==organization_id)

    queries = add_filters(
        dev_query = dev_query,
        gtw_query = gtw_query,
        asset_type = asset_type,
        asset_status = asset_status,
        gateway_ids = gateway_ids,
        device_ids = device_ids,
        min_signal_strength = min_signal_strength,
        max_signal_strength = max_signal_strength,
        min_packet_loss = min_packet_loss,
        max_packet_loss = max_packet_loss)    
    dev_query = queries[0]
    gtw_query = queries[1]
    
    result = query_for_count(dev_query = dev_query, gtw_query = gtw_query, asset_type = asset_type)

    counts = defaultdict(lambda: {'name' : None, 'count' : 0})
    
    if asset_type is not 'none':
        for row in result:
            counts[row.id]['name'] = row.gw_hex_id
            counts[row.id]['count'] += row.count_result

    return [{'id' : k, 'name':v['name'], 'count':v['count']} for k, v in counts.items()]

def count_per_signal_strength(organization_id, asset_type=None, asset_status=None, 
                    gateway_ids=None, device_ids=None,
                    min_signal_strength=None, max_signal_strength=None,
                    min_packet_loss=None, max_packet_loss=None):
    """ Count assets (devices+gateways) grouped by specific ranges of signal strength values
    Parameters: 
        - asset_type: for filtering, count only this type of asset ("device", "gateway" or "none" for no assets).
        - asset_status: for filtering, count only assets with this status ("connected" or "disconnected").
        - gateway_ids[]: for filtering, count only the assets connected to ANY one of these gateways.
        - device_ids[]: for filtering, list only the assets related to ANY of these devices
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
        filter(Device.organization_id==organization_id).\
        filter(Device.pending_first_connection==False)

    queries = add_filters(
        dev_query = dev_query,
        gtw_query = gtw_query,
        asset_type = asset_type,
        asset_status = asset_status,
        gateway_ids = gateway_ids,
        device_ids = device_ids,
        min_signal_strength = min_signal_strength,
        max_signal_strength = max_signal_strength,
        min_packet_loss = min_packet_loss,
        max_packet_loss = max_packet_loss)    
    dev_query = queries[0]
    gtw_query = queries[1]
    
    result = query_for_count(dev_query = dev_query, gtw_query = gtw_query, asset_type = asset_type)

    counts = defaultdict(lambda: {'name' : None, 'count' : 0})

    if asset_type is not 'none':
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
    else:
        for i in range(0, len(range_names)):
            name = range_names[i]
            L = range_limits[i]
            R = range_limits[i+1]
            counts[(L,R)]['name'] = name
            counts[(L,R)]['count'] = 0

    return [{'id' : k, 'name':v['name'], 'count':v['count']} for k, v in counts.items()]

def count_per_packet_loss(organization_id, asset_type=None, asset_status=None, 
                    gateway_ids=None, device_ids=None,
                    min_signal_strength=None, max_signal_strength=None,
                    min_packet_loss=None, max_packet_loss=None):
    """ Count assets (devices+gateways) grouped by specific ranges of packet loss values
    Parameters: 
        - asset_type: for filtering, count only this type of asset ("device", "gateway" or "none" for no assets).
        - asset_status: for filtering, count only assets with this status ("connected" or "disconnected").
        - gateway_ids[]: for filtering, count only the assets connected to ANY one of these gateways.
        - device_ids[]: for filtering, list only the assets related to ANY of these devices
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

    packets_up = build_count_subquery(CounterType.PACKETS_UP)
    packets_down = build_count_subquery(CounterType.PACKETS_DOWN)
    packets_lost = build_count_subquery(CounterType.PACKETS_LOST)

    dev_query = db.session.query()
    gtw_query = db.session.query()
    for i in range(0, len(range_names)):
        name = range_names[i]
        L = range_limits[i]
        R = range_limits[i+1]
        dev_query = dev_query.add_column(func.count(distinct(Device.id)).filter(and_(
            packets_up.c.count + packets_down.c.count + packets_lost.c.count > 0,
            L <= 100*packets_lost.c.count/(packets_up.c.count + packets_down.c.count + packets_lost.c.count),
            R > 100*packets_lost.c.count/(packets_up.c.count + packets_down.c.count + packets_lost.c.count),
            )).label(name))
        
        # Gateways are not considered because they don't have the loss value
        gtw_query = gtw_query.add_column(expression.literal_column("0").label(name))

    dev_query = dev_query.\
        select_from(Device).\
        filter(Device.organization_id==organization_id).\
        filter(Device.pending_first_connection==False).\
        join(packets_up, Device.id == packets_up.c.device_id).\
        join(packets_down, Device.id == packets_down.c.device_id).\
        join(packets_lost, Device.id == packets_lost.c.device_id)

    queries = add_filters(
        dev_query = dev_query,
        gtw_query = gtw_query,
        asset_type = asset_type,
        asset_status = asset_status,
        gateway_ids = gateway_ids,
        device_ids = device_ids,
        min_signal_strength = min_signal_strength,
        max_signal_strength = max_signal_strength,
        min_packet_loss = min_packet_loss,
        max_packet_loss = max_packet_loss)    
    dev_query = queries[0]
    gtw_query = queries[1]
    
    result = query_for_count(dev_query = dev_query, gtw_query = gtw_query, asset_type = asset_type)

    counts = defaultdict(lambda: {'name' : None, 'count' : 0})
    
    if asset_type is not 'none':
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
    else:
        for i in range(0, len(range_names)):
            name = range_names[i]
            L = range_limits[i]
            R = range_limits[i+1]
            counts[(L,R)]['name'] = name
            counts[(L,R)]['count'] = 0

    return [{'id' : k, 'name':v['name'], 'count':v['count']} for k, v in counts.items()]
    
def add_filters(dev_query, gtw_query, asset_type=None, asset_status=None, 
                gateway_ids=None, device_ids=None, 
                min_signal_strength=None, max_signal_strength=None,
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
        wanted_devs = db.session.\
            query(distinct(GatewayToDevice.device_id).label('device_id')).\
            filter(GatewayToDevice.gateway_id.in_(gateway_ids)).\
            subquery()

        dev_query = dev_query.join(wanted_devs, Device.id == wanted_devs.c.device_id)
        gtw_query = gtw_query.filter(Gateway.id.in_(gateway_ids))

    if device_ids:
        wanted_gtws = db.session.\
            query(distinct(GatewayToDevice.gateway_id).label('gateway_id')).\
            filter(GatewayToDevice.device_id.in_(device_ids)).\
            subquery()

        dev_query = dev_query.filter(Device.id.in_(device_ids))
        gtw_query = gtw_query.join(wanted_gtws, Gateway.id == wanted_gtws.c.gateway_id)

    if min_signal_strength is not None:
        dev_query = dev_query.filter(and_(Device.max_rssi != null(), Device.max_rssi >= min_signal_strength))
    if max_signal_strength is not None:
        dev_query = dev_query.filter(and_(Device.max_rssi != null(), Device.max_rssi < max_signal_strength))

    packets_up = build_count_subquery(CounterType.PACKETS_UP)
    packets_down = build_count_subquery(CounterType.PACKETS_DOWN)
    packets_lost = build_count_subquery(CounterType.PACKETS_LOST)

    if min_packet_loss is not None or max_packet_loss is not None:
        dev_query = dev_query.\
            join(packets_up, Device.id == packets_up.c.device_id).\
            join(packets_down, Device.id == packets_down.c.device_id).\
            join(packets_lost, Device.id == packets_lost.c.device_id)
    if min_packet_loss is not None:
        dev_query = dev_query.filter(and_(
            packets_up.c.count + packets_down.c.count + packets_lost.c.count > 0,
            100*packets_lost.c.count/(packets_up.c.count + packets_down.c.count + packets_lost.c.count) >= min_packet_loss
        ))
    if max_packet_loss is not None:
        dev_query = dev_query.filter(and_(
            packets_up.c.count + packets_down.c.count + packets_lost.c.count > 0,
            100*packets_lost.c.count/(packets_up.c.count + packets_down.c.count + packets_lost.c.count) < max_packet_loss
        ))

    return (dev_query, gtw_query)

def add_counters_columns(query, wanted_counters, asset_counters_cls):
    for counter_type in CounterType:
        if counter_type in wanted_counters:
            query = query.add_column(
                cast(
                    func.coalesce(func.sum(case([(asset_counters_cls.counter_type == counter_type, asset_counters_cls.value)], else_=0)), 0),
                    BigInteger
                ).label(counter_type.value)
            )
        else:
            query = query.add_column(cast(expression.null(), BigInteger).label(counter_type.value))
    return query

def build_count_subquery(counter_type):
    return db.session.query(DeviceCounters.device_id, func.coalesce(func.sum(DeviceCounters.value), 0).label('count')).\
        join(RowProcessed, RowProcessed.analyzer == 'packet_analyzer').\
        join(Packet, Packet.id == RowProcessed.last_row).\
        filter(DeviceCounters.counter_type == counter_type).\
        filter(DeviceCounters.last_update + func.make_interval(0,0,0,1) > Packet.date).\
        group_by(DeviceCounters.device_id).\
        subquery()

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
    elif asset_type == "none":
        result = []
    else:
        raise Error.BadRequest("Invalid asset type parameter")
    return result