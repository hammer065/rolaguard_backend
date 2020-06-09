import json
from flask import request, abort, jsonify
from flask_jwt_extended import get_jwt_identity
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity

import iot_logging
LOG = iot_logging.getLogger(__name__)

from sqlalchemy import func, or_
from sqlalchemy.sql import select, expression, text

from iot_api.user_api import db
from iot_api.user_api.model import User
from iot_api.user_api.Utils import is_admin_user, is_regular_user
from iot_api.user_api.model import Device, Gateway, DataCollectorToDevice, GatewayToDevice
from iot_api.user_api.models import DataCollector
from collections import defaultdict


class InventoryListAPI(Resource):
    """ Endpoint to list assets (devices + gateways)
    Request arguments (all optional):
    - page: for paginate.
    - size: for paginate.
    - vendor: for filtering, lists only assets with this vendor.
    - gateway_id: for filtering, list only this gateway and the devices connected to it.
    - data_collector_id: for filtering, list only the assest related to this data collector.
    - device_type: for filtering, list only this type of devices ("device" or "gateway").
    Returns:
    JSON with list of assets (see code for more details about the sub fields).
    """
    @jwt_required
    def get(self):
        try:
            user_identity = get_jwt_identity()
            user = User.find_by_username(user_identity)
            if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
                return abort(403, error='forbidden access')

            organization_id = user.organization_id
            page = request.args.get('page', default=1, type=int)
            size = request.args.get('size', default=20, type=int)
            
            vendor = request.args.get('vendor', default=None, type=str)
            gateway_id = request.args.get('gateway_id', default=None, type=int)
            data_collector_id = request.args.get('data_collector_id', default=None, type=int)
            device_type = request.args.get('device_type', default=None, type=str)

            # Build two queries, one for devices and one for gateways
            s1 = select([
                Device.dev_eui.label('id'),
                expression.literal_column('\'Device\'').label('type'),
                Device.name,
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
                Gateway.name,
                DataCollector.name.label('data_collector'),
                Gateway.vendor
                ]).\
                    where(Gateway.organization_id == organization_id).\
                    where(Gateway.data_collector_id == DataCollector.id)

            # If filter parameters were given, add the respective where clauses to the queries
            if vendor:
                s1 = s1.where(Device.vendor == vendor)
                s2 = s2.where(Gateway.vendor == vendor)
            if gateway_id:
                s1 = s1.where(GatewayToDevice.gateway_id == gateway_id)
                s2 = s2.where(Gateway.id == gateway_id)
            if data_collector_id:
                s1 = s1.where(DataCollector.id == data_collector_id)
                s2 = s2.where(DataCollector.id == data_collector_id)

            # Filter by device type if the parameter was given, else, make a union with queries.
            query = s1.union(s2)
            if device_type:
                if device_type == "device":
                    query = s1
                elif device_type == "gateway":
                    query = s2
                else:
                    raise Exception("Invalid device type parameter")

            # Execute the queries and join the results
            query = query.order_by(text('type desc'))
            query = query.alias('device_gateway')
            results = db.session.query(query).paginate(page=page, per_page=size)

            devices = [{
                'id' : dev.id,
                'type' : dev.type,
                'name' : dev.name,
                'data_collector' : dev.data_collector,
                'vendor' : dev.vendor,
                'application' : None,
                'tags' : []
            } for dev in results.items]
            headers = {'total-pages': results.pages, 'total-items': results.total}
            return {"devices": devices}, 200, headers
        except Exception as e:
            LOG.error(f"Error: {e}")
            return {"message" : str(e)}, 400


class InventoryCountAPI(Resource):
    """ Endpoint to count assets (devices + gateways). It simply parses the arguments and call
    the functions to count the assets.
    Request arguments (all optional):
    - vendor: for filtering, counts only assets with this vendor.
    - gateway_id: for filtering, only counts this gateway and the devices connected to it.
    - data_collector_id: for filtering, only counts the assest related to this data collector.
    - device_type: for filtering, only counts this type of devices ("device" or "gateway").
    Returns:
    - A JSON with 4 fields, the names are self-explanatory: n_assets_per_vendor, n_assets_per_gateway, 
        n_assets_per_datacollector, n_assets_per_tags
    """
    @jwt_required
    def get(self):
        try:
            user_identity = get_jwt_identity()
            user = User.find_by_username(user_identity)
            if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
                return abort(403, error='forbidden access')
            organization_id = user.organization_id

            vendor = request.args.get('vendor', default=None, type=str)
            gateway_id = request.args.get('gateway_id', default=None, type=int)
            data_collector_id = request.args.get('data_collector_id', default=None, type=int)
            device_type = request.args.get('device_type', default=None, type=str)

            response = {
                'n_assets_per_vendor' : n_asset_per_vendor(
                    organization_id,
                    vendor=vendor,
                    gateway_id=gateway_id,
                    data_collector_id=data_collector_id,
                    device_type=device_type
                ),
                'n_assets_per_gateway' : n_asset_per_gateway(
                    organization_id,
                    vendor=vendor,
                    gateway_id=gateway_id,
                    data_collector_id=data_collector_id,
                    device_type=device_type
                ),
                'n_assets_per_datacollector' : n_asset_per_datacollector(
                    organization_id,
                    vendor=vendor,
                    gateway_id=gateway_id,
                    data_collector_id=data_collector_id,
                    device_type=device_type
                ),
                'n_assets_per_tag' : n_asset_per_tag(
                    organization_id,
                    vendor=vendor,
                    gateway_id=gateway_id,
                    data_collector_id=data_collector_id,
                    device_type=device_type
                ),
            }

            return response, 200
        except Exception as e:
            LOG.error(f"Error: {e}")
            return {"message" : str(e)}, 400


def n_asset_per_vendor(organization_id, vendor=None, gateway_id=None, data_collector_id=None, device_type=None):
    """ Count the number of assets per vendor. All the parameters are for filtering """
    # Build two queries, one for devices and one for gateways
    s1 = db.session.query(Device.vendor, func.count(Device.id)).\
        join(GatewayToDevice).\
        join(DataCollectorToDevice).\
        group_by(Device.vendor).\
        filter(Device.organization_id==organization_id)

    s2 = db.session.query(Gateway.vendor, func.count(Gateway.id)).\
        group_by(Gateway.vendor).\
        filter(Gateway.organization_id==organization_id)

    # If the filtering arguments are given, add the respective where clauses to the queries
    if vendor:
        s1 = s1.filter(Device.vendor==vendor)
        s2 = s2.filter(Gateway.vendor==vendor)
    if gateway_id:
        s1 = s1.filter(GatewayToDevice.gateway_id == gateway_id)
        s2 = s2.filter(Gateway.id == gateway_id)
    if data_collector_id:
        s1 = s1.filter(DataCollector.id == data_collector_id)
        s2 = s2.filter(Gateway.data_collector_id == data_collector_id)

    # Execute the queries, filtering by asset type
    all_queries = None
    if device_type == "device":
        all_queries = s1.all()
    elif device_type == "gateway":
        all_queries = s2.all()
    elif device_type is None:
        all_queries = s1.all() + s2.all()

    counts = defaultdict(lambda: 0)
    for e in all_queries:
        counts[e[0]] += e[1]
    return dict(counts)


def n_asset_per_gateway(organization_id, vendor=None, gateway_id=None, data_collector_id=None, device_type=None):
    """ Count the number of assets per gateway. All the parameters are for filtering """
    # Query to count the number of devices per gateway
    query = db.session.query(Gateway.gw_hex_id, func.count(Gateway.gw_hex_id)).\
        join(GatewayToDevice).\
        join(Device).\
        group_by(Gateway.gw_hex_id).\
        filter(Gateway.organization_id==organization_id)
    
    # If the arguments are given, filter adding the respective where clause
    if vendor:
        query=query.filter(or_(Device.vendor==vendor, Gateway.vendor==vendor))
    if gateway_id:
        query=query.filter(Gateway.id==gateway_id)
    if data_collector_id:
        query=query.filter(Gateway.data_collector_id==data_collector_id)
    
    # Execute the query and build the response
    counts = defaultdict(lambda: 1) # Starts with one because the gateway counts as an asset
    for e in query.all():
        counts[e[0]] += e[1] # Sum the number of devices per gateway + 1 (the gateway)
        if device_type=="device":
            counts[e[0]]-= 1 # Subtract one because the gateway has not to be taken into account
        elif device_type=="gateway":
            counts[e[0]] = 1 # If only want to count gateways, the response is always one per gateway_id
    return dict(counts)


def n_asset_per_datacollector(organization_id, vendor=None, gateway_id=None, data_collector_id=None, device_type=None):
    """ Count the number of assets per data collector. All the parameters are for filtering """
    # Base queries, one for devices and one for gateways
    s1 = db.session.query(DataCollector.name, func.count(DataCollector.id)).\
        join(DataCollectorToDevice).\
        join(Device).\
        group_by(DataCollector.id).\
        filter(DataCollector.organization_id == organization_id)
    s2 = db.session.query(DataCollector.name, func.count(DataCollector.id)).\
        join(Gateway).\
        group_by(DataCollector.id).\
        filter(DataCollector.organization_id==organization_id)

    # If some filtering parameters are giveng, add the respective where clauses to the queries
    if vendor:
        s1 = s1.filter(Device.vendor==vendor)
        s2 = s2.filter(Gateway.vendor==vendor)
    if gateway_id:
        s1 = s1.filter(GatewayToDevice.gateway_id == gateway_id)
        s2 = s2.filter(Gateway.id == gateway_id)
    if data_collector_id:
        s1 = s1.filter(DataCollector.id == data_collector_id)
        s2 = s2.filter(Gateway.data_collector_id == data_collector_id)

    # Run the queries
    dev_per_dc = s1.all()
    gw_per_dc = s1.all()

    # Filter the queries by asset type if the parameter is given
    all_queries = []
    if device_type == "device":
        all_queries = dev_per_dc
    elif device_type == "gateway":
        all_queries = gw_per_dc
    elif device_type is None:
        all_queries = dev_per_dc + gw_per_dc

    # Join the results of the queries
    counts = defaultdict(lambda: 0)
    for e in dev_per_dc + gw_per_dc:
        counts[e[0]] += e[1]
    return dict(counts)


def n_asset_per_tag(organization_id, vendor=None, gateway_id=None, data_collector_id=None, device_type=None):
    """ Count the number of assets per tag. All the parameters are for filtering """
    """ TODO: this function returns the total number of assets since we dont have tags for now """
    total_devs = db.session.query(func.count(Device.id)).\
        filter(Device.organization_id==organization_id).all()
    total_gws = db.session.query(func.count(Gateway.id)).\
        filter(Gateway.organization_id==organization_id).all()
    total = total_devs[0][0] + total_gws[0][0]
    return {None : total}
