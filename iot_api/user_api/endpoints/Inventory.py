from flask import request, abort
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity

import iot_logging
LOG = iot_logging.getLogger(__name__)

from iot_api.user_api.model import User
from iot_api.user_api.Utils import is_system
from iot_api.user_api.repository import InventoryAssets


class AssetsListAPI(Resource):
    """ Endpoint to list assets (devices + gateways)
    Request parameters (all optional):
        - page: for pagination.
        - size: for pagination.
        - vendors[]: for filtering, lists only assets that have ANY one of these vendors.
        - gateway_ids[]: for filtering, list only the assets connected to ANY one of these gateways.
        - data_collector_ids[]: for filtering, list only the assest related to ANY of these data collectors.
        - tag_ids[]: for filtering, list only the assest that have ALL these tags.
        - asset_type: for filtering, list only this type of asset ("device" or "gateway").
    Returns:
        - JSON with list of assets (see code for more details about the fields).
    """
    @jwt_required
    def get(self):
        try:
            user = User.find_by_username(get_jwt_identity())
            if not user or is_system(user.id):
                return abort(403, error='forbidden access')

            organization_id = user.organization_id
            page = request.args.get('page', default=1, type=int)
            size = request.args.get('size', default=20, type=int)
            
            results = InventoryAssets.list_all(
                organization_id=organization_id,
                page=page, size=size,
                vendors=request.args.getlist('vendors[]'),
                gateway_ids=request.args.getlist('gateway_ids[]'),
                data_collector_ids=request.args.getlist('data_collector_ids[]'),
                tag_ids=request.args.getlist('data_collector_ids[]'),
                asset_type=request.args.get('asset_type', type=str)
            )

            devices = [{
                'id' : dev.id,
                'type' : dev.type,
                'name' : dev.name,
                'data_collector' : dev.data_collector,
                'vendor' : dev.vendor,
                'app_name' : dev.app_name,
                'join_eui' : dev.join_eui,
                'tags' : []
            } for dev in results.items]
            response = {
                'assets' : devices,
                'total_pages': results.pages,
                'total_items': results.total
            }
            return response, 200
        except Exception as e:
            LOG.error(f"Error: {e}")
            return {"message" : "There was an error trying to list assets"}, 400


class AssetsPerVendorCountAPI(Resource):
    """ Endpoint to count assets (devices+gateways) grouped by vendor.
    Request parameters: 
        - vendors[]: for filtering, lists only assets that have ANY one of these vendors.
        - gateway_ids[]: for filtering, list only the assets connected to ANY one of these gateways.
        - data_collector_ids[]: for filtering, list only the assest related to ANY of these data collectors.
        - tag_ids[]: for filtering, list only the assest that have ALL these tags.
        - asset_type: for filtering, list only this type of asset ("device" or "gateway").
    Returns:
        - A list of JSONs, where each JSON has three fields: id, name, count.
    """
    @jwt_required
    def get(self):
        try:
            user_identity = get_jwt_identity()
            user = User.find_by_username(user_identity)
            if not user or is_system(user.id):
                return abort(403, error='forbidden access')
            organization_id = user.organization_id

            response = InventoryAssets.count_per_vendor(
                organization_id = organization_id,
                vendors = request.args.getlist('vendors[]'),
                gateway_ids = request.args.getlist('gateway_ids[]'),
                data_collector_ids = request.args.getlist('data_collector_ids[]'),
                tag_ids = request.args.getlist('tag_ids[]'),
                asset_type = request.args.get('asset_type', default=None, type=str)
            )

            return response, 200
        except Exception as e:
            LOG.error(f"Error: {e}")
            return {"message" : "There was an error trying to count assets"}, 400

class AssetsPerGatewayCountAPI(Resource):
    """ Endpoint to count assets (devices+gateways) grouped by gateway.
    Request parameters: 
        - vendors[]: for filtering, lists only assets that have ANY one of these vendors.
        - gateway_ids[]: for filtering, list only the assets connected to ANY one of these gateways.
        - data_collector_ids[]: for filtering, list only the assest related to ANY of these data collectors.
        - tag_ids[]: for filtering, list only the assest that have ALL these tags.
        - asset_type: for filtering, list only this type of asset ("device" or "gateway").
    Returns:
        - A list of JSONs, where each JSON has three fields: id, name, count.
    """
    @jwt_required
    def get(self):
        try:
            user_identity = get_jwt_identity()
            user = User.find_by_username(user_identity)
            if not user or is_system(user.id):
                return abort(403, error='forbidden access')
            organization_id = user.organization_id

            response = InventoryAssets.count_per_gateway(
                organization_id = organization_id,
                vendors = request.args.getlist('vendors[]'),
                gateway_ids = request.args.getlist('gateway_ids[]'),
                data_collector_ids = request.args.getlist('data_collector_ids[]'),
                tag_ids = request.args.getlist('tag_ids[]'),
                asset_type = request.args.get('asset_type', default=None, type=str)
            )

            return response, 200
        except Exception as e:
            LOG.error(f"Error: {e}")
            return {"message" : "There was an error trying to count assets"}, 400
            

class AssetsPerDatacollectorCountAPI(Resource):
    """ Endpoint to count assets (devices+gateways) grouped per data-collector .
    Request parameters: 
        - vendors[]: for filtering, lists only assets that have ANY one of these vendors.
        - gateway_ids[]: for filtering, list only the assets connected to ANY one of these gateways.
        - data_collector_ids[]: for filtering, list only the assest related to ANY of these data collectors.
        - tag_ids[]: for filtering, list only the assest that have ALL these tags.
        - asset_type: for filtering, list only this type of asset ("device" or "gateway").
    Returns:
        - A list of JSONs, where each JSON has three fields: id, name, count.
    """
    @jwt_required
    def get(self):
        try:
            user_identity = get_jwt_identity()
            user = User.find_by_username(user_identity)
            if not user or is_system(user.id):
                return abort(403, error='forbidden access')
            organization_id = user.organization_id

            response = InventoryAssets.count_per_datacollector(
                organization_id = organization_id,
                vendors = request.args.getlist('vendors[]'),
                gateway_ids = request.args.getlist('gateway_ids[]'),
                data_collector_ids = request.args.getlist('data_collector_ids[]'),
                tag_ids = request.args.getlist('tag_ids[]'),
                asset_type = request.args.get('asset_type', default=None, type=str)
            )

            return response, 200
        except Exception as e:
            LOG.error(f"Error: {e}")
            return {"message" : "There was an error trying to count assets"}, 400


class AssetsPerTagCountAPI(Resource):
    """ Endpoint to count assets (devices+gateways) grouped per tag.
    Request parameters: 
        - vendors[]: for filtering, lists only assets that have ANY one of these vendors.
        - gateway_ids[]: for filtering, list only the assets connected to ANY one of these gateways.
        - data_collector_ids[]: for filtering, list only the assest related to ANY of these data collectors.
        - tag_ids[]: for filtering, list only the assest that have ALL these tags.
        - asset_type: for filtering, list only this type of asset ("device" or "gateway").
    Returns:
        - A list of JSONs, where each JSON has three fields: id, name, count.
    """
    @jwt_required
    def get(self):
        try:
            user_identity = get_jwt_identity()
            user = User.find_by_username(user_identity)
            if not user or is_system(user.id):
                return abort(403, error='forbidden access')
            organization_id = user.organization_id

            response = InventoryAssets.count_per_tag(
                organization_id = organization_id,
                vendors = request.args.getlist('vendors[]'),
                gateway_ids = request.args.getlist('gateway_ids[]'),
                data_collector_ids = request.args.getlist('data_collector_ids[]'),
                tag_ids = request.args.getlist('tag_ids[]'),
                asset_type = request.args.get('asset_type', default=None, type=str)
            )
            return response, 200

        except Exception as e:
            LOG.error(f"Error: {e}")
            return {"message" : "There was an error trying to count assets"}, 400

