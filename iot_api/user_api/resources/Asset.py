from flask import request
from flask_restful import Resource
from flask_jwt_extended import get_jwt_claims

import iot_logging, calendar, json, math
log = iot_logging.getLogger(__name__)

from collections import namedtuple

from iot_api.user_api.model import User
from iot_api.user_api.Utils import is_system
from iot_api.user_api.JwtUtils import admin_regular_allowed
from iot_api.user_api.repository import AssetRepository
from iot_api.user_api import Error

class AssetListAPI(Resource):
    """ Endpoint to list assets (devices + gateways)
    Request parameters (all optional):
        - page: for pagination.
        - size: for pagination.
        - search_param
        - asset_type: for filtering, count only this type of asset ("device" or "gateway").
        - asset_status: for filtering, count only assets with this status ("connected" or "disconnected").
        - data_collector_ids[]: for filtering, count only the assets belongs to these data collectors.
        - gateway_ids[]: for filtering, count only the assets connected to ANY one of these gateways.
        - tag_ids[]: for filtering, list only the assest that have ALL these tags.
        - importances: for filtering, list only the assets that have ANY of these importances
    Returns:
        - JSON with list of devices, devices_ids, gateways.
    """
    @admin_regular_allowed
    def get(self):
        assets = AssetRepository.search(
            organization_id = get_jwt_claims().get('organization_id'),
            page = request.args.get('page', default=1, type=int),
            size = request.args.get('size', default=3, type=int),
            page_ids = request.args.get('page_ids', default=1, type=int),
            size_ids = request.args.get('size_ids', default=20, type=int),
            search_param = request.args.get('search_param', default=None),
            asset_type = request.args.get('asset_type', default=None, type=str),
            asset_status = request.args.get('asset_status', default=None, type=str),
            data_collector_ids=request.args.getlist('data_collector_ids[]'),
            gateway_ids = request.args.getlist('gateway_ids[]'),
            tag_ids = request.args.getlist('tag_ids[]'),
            importances = request.args.get('importances')
        )
            
        # @todo: fix the next lines for return from model
        devices_ids = [device.id for device in assets['device_ids'].items]
        gateway_ids = [gateway.id for gateway in assets['gateway_ids'].items]

        response = {
            'devices': {
                'items': [d._asdict() for d in assets['devices'].items],
                'items_ids': devices_ids,                
                'total_pages': assets['devices'].pages,
                'total_items': assets['devices'].total,
            },
            'gateways': {
                'items': [g._asdict() for g in assets['gateways'].items],
                'items_ids': gateway_ids,
                'total_pages': assets['gateways'].pages,
                'total_items': assets['gateways'].total,
            }
        }
        return response, 200
