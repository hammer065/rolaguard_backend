from flask import request, abort, jsonify
from flask_jwt_extended import get_jwt_identity
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity

import iot_logging
log = iot_logging.getLogger(__name__)

from sqlalchemy import func, or_, distinct
from sqlalchemy.sql import select, expression, text

from iot_api.user_api import db
from iot_api.user_api.model import User
from iot_api.user_api.Utils import is_admin_user, is_regular_user
from iot_api.user_api.model import Device, Gateway, DataCollectorToDevice, GatewayToDevice
from iot_api.user_api.models import DataCollector
from collections import defaultdict


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
    s1 = select([
        Device.dev_eui.label('id'),
        expression.literal_column('\'Device\'').label('type'),
        Device.join_eui.label('join_eui'),
        Device.name,
        Device.app_name,
        DataCollector.name.label('data_collector'),
        Device.vendor
        ]).\
            where(Device.organization_id==organization_id).\
            where(Device.id==DataCollectorToDevice.device_id).\
            where(DataCollector.id==DataCollectorToDevice.data_collector_id).\
            where(GatewayToDevice.device_id==Device.id)
    s2 = select([
        Gateway.gw_hex_id.label('id'),
        expression.literal_column('\'Gateway\'').label('type'),
        expression.null().label('join_eui'),
        Gateway.name,
        expression.null().label('app_name'),
        DataCollector.name.label('data_collector'),
        Gateway.vendor
        ]).\
            where(Gateway.organization_id == organization_id).\
            where(Gateway.data_collector_id == DataCollector.id)

    # If filter parameters were given, add the respective where clauses to the queries
    if vendors:
        s1 = s1.where(Device.vendor.in_(vendors))
        s2 = s2.where(Gateway.vendor.in_(vendors))
    if gateway_ids:
        s1 = s1.where(GatewayToDevice.gateway_id.in_(gateway_ids))
        s2 = s2.where(Gateway.id.in_(gateway_ids))
    if data_collector_ids:
        s1 = s1.where(DataCollector.id.in_(data_collector_ids))
        s2 = s2.where(DataCollector.id.in_(data_collector_ids))
    if tag_ids:
        pass # TODO: implement AND tag filtering

    # Filter by device type if the parameter was given, else, make a union with queries.
    query = s1.union(s2)
    if asset_type:
        if asset_type == "device":
            query = s1
        elif asset_type == "gateway":
            query = s2
        else:
            raise Exception("Invalid device type parameter")

    # Execute the queries and join the results
    query = query.order_by(text('type desc'))
    query = query.alias('device_gateway')
    if page and size:
        return db.session.query(query).paginate(page=page, per_page=size, error_out=False)
    else:
        return db.session.query(query)


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
    s1 = db.session.query(Device.vendor, func.count(Device.id)).\
        join(DataCollectorToDevice).\
        group_by(Device.vendor).\
        filter(Device.organization_id==organization_id)

    s2 = db.session.query(Gateway.vendor, func.count(Gateway.id)).\
        group_by(Gateway.vendor).\
        filter(Gateway.organization_id==organization_id)

    # If the filtering arguments are given, add the respective where clauses to the queries
    if vendors:
        s1 = s1.filter(Device.vendor.in_(vendors))
        s2 = s2.filter(Gateway.vendor.in_(vendors))
    if gateway_ids:
        s1 = s1.filter(GatewayToDevice.gateway_id.in_(gateway_ids))
        s2 = s2.filter(Gateway.id.in_(gateway_ids))
    if data_collector_ids:
        s1 = s1.filter(DataCollector.id.in_(data_collector_ids))
        s2 = s2.filter(Gateway.data_collector_id.in_(data_collector_ids))
    if tag_ids:
        pass # TODO: implement AND tag filtering

    # Execute the queries, filtering by asset type
    all_queries = None
    if asset_type == "device":
        all_queries = s1.all()
    elif asset_type == "gateway":
        all_queries = s2.all()
    elif asset_type is None:
        all_queries = s1.all() + s2.all()

    counts = defaultdict(lambda: {'name' : None, 'count' : 0})
    for e in all_queries:
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
    query = db.session.query(Gateway.id, Gateway.gw_hex_id, func.count(Gateway.gw_hex_id)).\
        join(GatewayToDevice).\
        join(Device).\
        group_by(Gateway.id, Gateway.gw_hex_id).\
        filter(Gateway.organization_id==organization_id)
    
    # If the arguments are given, filter adding the respective where clause
    if vendors:
        query=query.filter(Device.vendor.in_(vendors)) 
        # TODO: is not counting the gateways 
    if gateway_ids:
        query=query.filter(Gateway.id.in_(gateway_ids))
    if data_collector_ids:
        query=query.filter(Gateway.data_collector_id.in_(data_collector_ids))
    
    # Execute the query and build the response
    counts = defaultdict(lambda: {'name' : None, 'count' : 1}) # Starts with one because the gateway counts as an asset
    for e in query.all():
        counts[e[0]]['name'] = e[1]
        counts[e[0]]['count'] += e[2] # Sum the number of devices per gateway + 1 (the gateway)
        if asset_type=="device":
            counts[e[0]]['count']-= 1 # Subtract one because the gateway has not to be taken into account
        elif asset_type=="gateway":
            counts[e[0]]['count'] = 1 # If only want to count gateways, the response is always one per gateway_id
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
    s1 = db.session.query(DataCollector.id, DataCollector.name, func.count(distinct(Device.id))).\
        select_from(Device).\
        join(DataCollectorToDevice).join(DataCollector).\
        join(GatewayToDevice).join(Gateway).\
        group_by(DataCollector.id, DataCollector.name).\
        filter(DataCollector.organization_id == organization_id)
    s2 = db.session.query(DataCollector.id, DataCollector.name, func.count(DataCollector.id)).\
        join(Gateway).\
        group_by(DataCollector.id, DataCollector.name).\
        filter(DataCollector.organization_id==organization_id)

    # If some filtering parameters are giveng, add the respective where clauses to the queries
    if vendors:
        s1 = s1.filter(Device.vendor.in_(vendors))
        s2 = s2.filter(Gateway.vendor.in_(vendors))
    if gateway_ids:
        s1 = s1.filter(Gateway.id.in_(gateway_ids))
        s2 = s2.filter(Gateway.id.in_(gateway_ids))
    if data_collector_ids:
        s1 = s1.filter(DataCollector.id.in_(data_collector_ids))
        s2 = s2.filter(Gateway.data_collector_id.in_(data_collector_ids))
    if tag_ids:
        pass # TODO: implement AND tag filtering

    # Run the queries
    dev_per_dc = s1.all()
    gw_per_dc = s2.all()

    # Filter the queries by asset type if the parameter is given
    all_queries = []
    if asset_type == "device":
        all_queries = dev_per_dc
    elif asset_type == "gateway":
        all_queries = gw_per_dc
    elif asset_type is None:
        all_queries = dev_per_dc + gw_per_dc

    # Join the results of the queries
    counts = defaultdict(lambda: {'name' : None, 'count' : 0})
    for e in dev_per_dc + gw_per_dc:
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
    # TODO: this function returns the total number of assets since we dont have tags for now
    total_devs = db.session.query(func.count(Device.id)).\
        filter(Device.organization_id==organization_id).all()
    total_gws = db.session.query(func.count(Gateway.id)).\
        filter(Gateway.organization_id==organization_id).all()
    total = total_devs[0][0] + total_gws[0][0]
    return [{'id' : None, 'name' : None, 'count' : total}]
