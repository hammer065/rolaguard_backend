import json
from flask import request, abort, jsonify
from flask_jwt_extended import get_jwt_identity
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity

import iot_logging
LOG = iot_logging.getLogger(__name__)

from sqlalchemy import func
from sqlalchemy.sql import select, expression, text

from iot_api.user_api import db
from iot_api.user_api.model import User
from iot_api.user_api.Utils import is_admin_user, is_regular_user
from iot_api.user_api.model import Device, Gateway, DataCollectorToDevice, GatewayToDevice
from iot_api.user_api.models import DataCollector
from collections import defaultdict


class InventoryListAPI(Resource):
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

            s1 = select([Device.dev_eui.label('id'),
                expression.literal_column('\'Device\'').label('type'),
                Device.name,
                DataCollector.name.label('data_collector'),
                Device.vendor]).\
                    where(Device.organization_id == organization_id).\
                    where(Device.id==DataCollectorToDevice.device_id).\
                    where(DataCollector.id==DataCollectorToDevice.data_collector_id)
            s2 = select([Gateway.gw_hex_id.label('id'),
                    expression.literal_column('\'Gateway\'').label('type'),
                    Gateway.name,
                    DataCollector.name.label('data_collector'),
                    Gateway.vendor]).\
                 where(Gateway.organization_id == organization_id).\
                 where(Gateway.data_collector_id == DataCollector.id)

            q = s1.union(s2)
            q = q.order_by(text('type desc'))
            q = q.alias('device_gateway')

            res = db.session.query(Device.app_name, func.count(Device.app_name)).group_by(Device.app_name).all()
            results = db.session.query(q).paginate(page=page, per_page=size)

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
    @jwt_required
    def get(self):
        try:
            user_identity = get_jwt_identity()
            user = User.find_by_username(user_identity)
            if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
                return abort(403, error='forbidden access')
            organization_id = user.organization_id

            response = {
                'n_assets_per_vendor' : n_asset_per_vendor(organization_id),
                'n_assets_per_gateway' : n_asset_per_gateway(organization_id),
                'n_assets_per_datacollector' : n_asset_per_datacollector(organization_id),
                'n_assets_per_tag' : n_asset_per_tag(organization_id)
            }

            return response, 200
        except Exception as e:
            LOG.error(f"Error: {e}")
            return {"message" : str(e)}, 400


def n_asset_per_vendor(organization_id, vendor=None, gateway_id=None, data_collector_id=None, type=None):
    query = db.session.query(Device.vendor, func.count(Device.vendor)).\
        group_by(Device.vendor).\
        filter(Device.organization_id==organization_id)
    dev_per_vendor = query.all()

    query = db.session.query(Gateway.vendor, func.count(Gateway.vendor)).\
        group_by(Gateway.vendor).\
        filter(Gateway.organization_id==organization_id)
    gw_per_vendor = query.all()
    counts = defaultdict(lambda: 0)
    for e in dev_per_vendor + gw_per_vendor:
        counts[e[0]] += e[1]
    return dict(counts)

def n_asset_per_gateway(organization_id):
    dev_per_gw = db.session.query(Gateway.gw_hex_id, func.count(Gateway.gw_hex_id)).\
        join(GatewayToDevice).\
        group_by(Gateway.gw_hex_id).\
        filter(Gateway.organization_id==organization_id).all()
    counts = defaultdict(lambda: 1) # One because the gateway counts as an asset
    for e in dev_per_gw:
        if e[0]: counts[e[0]] += e[1]
    return dict(counts)

def n_asset_per_datacollector(organization_id):
    dev_per_dc = db.session.query(DataCollector.name, func.count(DataCollector.id)).\
        join(DataCollectorToDevice).\
        group_by(DataCollector.id).\
        filter(DataCollector.organization_id == organization_id).all()
    gw_per_dc = db.session.query(DataCollector.name, func.count(DataCollector.id)).\
        join(Gateway).\
        group_by(DataCollector.id).\
        filter(DataCollector.organization_id==organization_id).all()
    counts = defaultdict(lambda: 0)
    for e in dev_per_dc + gw_per_dc:
        if e[0]: counts[e[0]] += e[1]
    return dict(counts)


def n_asset_per_tag(organization_id):
    total_devs = db.session.query(func.count(Device.id)).\
        filter(Device.organization_id==organization_id).all()
    total_gws = db.session.query(func.count(Gateway.id)).\
        filter(Gateway.organization_id==organization_id).all()
    total = total_devs[0][0] + total_gws[0][0]
    return {None : total}
