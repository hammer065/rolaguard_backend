from flask import request, abort
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity

import iot_logging
LOG = iot_logging.getLogger(__name__)

from iot_api.user_api.model import User
from iot_api.user_api.Utils import is_system
from iot_api.user_api.repository import Assets


class AssetsListAPI(Resource):
    """ Endpoint to list assets (devices + gateways)
    Request arguments (all optional):
    - page: for pagination.
    - size: for pagination.
    - vendor: for filtering, lists only assets with this vendor.
    - gateway_id: for filtering, list only this gateway and the devices connected to it.
    - data_collector_id: for filtering, list only the assest related to this data collector.
    - asset_type: for filtering, list only this type of devices ("device" or "gateway").
    Returns:
    JSON with list of assets (see code for more details about the sub fields).
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
            
            results = Assets.list_all(
                organization_id=organization_id,
                page=page, size=size,
                vendor = request.args.get('vendor', default=None, type=str),
                gateway_id = request.args.get('gateway_id', default=None, type=int),
                data_collector_id = request.args.get('data_collector_id', default=None, type=int),
                asset_type = request.args.get('asset_type', default=None, type=str)
            )

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
            return {"message" : "There was an error trying to list assets"}, 400


class AssetsPerVendorCountAPI(Resource):
    """ Endpoint to count assets grouped per vendor (devices + gateways).
    Request arguments (all optional):
    - vendor: for filtering, counts only assets with this vendor.
    - gateway_id: for filtering, only counts this gateway and the devices connected to it.
    - data_collector_id: for filtering, only counts the assest related to this data collector.
    - asset_type: for filtering, only counts this type of devices ("device" or "gateway").
    Returns:
    - A JSON with 4 fields, the names are self-explanatory: n_assets_per_vendor, n_assets_per_gateway, 
        n_assets_per_datacollector, n_assets_per_tags
    """
    @jwt_required
    def get(self):
        try:
            user_identity = get_jwt_identity()
            user = User.find_by_username(user_identity)
            if not user or is_system(user.id):
                return abort(403, error='forbidden access')
            organization_id = user.organization_id

            vendor = request.args.get('vendor', default=None, type=str)
            gateway_id = request.args.get('gateway_id', default=None, type=int)
            data_collector_id = request.args.get('data_collector_id', default=None, type=int)
            asset_type = request.args.get('asset_type', default=None, type=str)

            response = Assets.count_per_vendor(
                organization_id,
                vendor=vendor,
                gateway_id=gateway_id,
                data_collector_id=data_collector_id,
                asset_type=asset_type
            )

            return response, 200
        except Exception as e:
            LOG.error(f"Error: {e}")
            return {"message" : "There was an error trying to count assets"}, 400

class AssetsPerGatewayCountAPI(Resource):
    """ Endpoint to count assets grouped by gateway (devices + gateways).
    Request arguments (all optional):
    - vendor: for filtering, counts only assets with this vendor.
    - gateway_id: for filtering, only counts this gateway and the devices connected to it.
    - data_collector_id: for filtering, only counts the assest related to this data collector.
    - asset_type: for filtering, only counts this type of devices ("device" or "gateway").
    Returns:
    - A JSON with 4 fields, the names are self-explanatory: n_assets_per_vendor, n_assets_per_gateway, 
        n_assets_per_datacollector, n_assets_per_tags
    """
    @jwt_required
    def get(self):
        try:
            user_identity = get_jwt_identity()
            user = User.find_by_username(user_identity)
            if not user or is_system(user.id):
                return abort(403, error='forbidden access')
            organization_id = user.organization_id

            vendor = request.args.get('vendor', default=None, type=str)
            gateway_id = request.args.get('gateway_id', default=None, type=int)
            data_collector_id = request.args.get('data_collector_id', default=None, type=int)
            asset_type = request.args.get('asset_type', default=None, type=str)

            response = Assets.count_per_gateway(
                organization_id,
                vendor=vendor,
                gateway_id=gateway_id,
                data_collector_id=data_collector_id,
                asset_type=asset_type
            )

            return response, 200
        except Exception as e:
            LOG.error(f"Error: {e}")
            return {"message" : "There was an error trying to count assets"}, 400
            

class AssetsPerDatacollectorCountAPI(Resource):
    """ Endpoint to count assets (devices + gateways). It simply parses the arguments and call
    the functions to count the assets.
    Request arguments (all optional):
    - vendor: for filtering, counts only assets with this vendor.
    - gateway_id: for filtering, only counts this gateway and the devices connected to it.
    - data_collector_id: for filtering, only counts the assest related to this data collector.
    - asset_type: for filtering, only counts this type of devices ("device" or "gateway").
    Returns:
    - A JSON with 4 fields, the names are self-explanatory: n_assets_per_vendor, n_assets_per_gateway, 
        n_assets_per_datacollector, n_assets_per_tags
    """
    @jwt_required
    def get(self):
        try:
            user_identity = get_jwt_identity()
            user = User.find_by_username(user_identity)
            if not user or is_system(user.id):
                return abort(403, error='forbidden access')
            organization_id = user.organization_id

            vendor = request.args.get('vendor', default=None, type=str)
            gateway_id = request.args.get('gateway_id', default=None, type=int)
            data_collector_id = request.args.get('data_collector_id', default=None, type=int)
            asset_type = request.args.get('asset_type', default=None, type=str)

            response = Assets.count_per_datacollector(
                organization_id,
                vendor=vendor,
                gateway_id=gateway_id,
                data_collector_id=data_collector_id,
                asset_type=asset_type
            )

            return response, 200
        except Exception as e:
            LOG.error(f"Error: {e}")
            return {"message" : "There was an error trying to count assets"}, 400


class AssetsPerTagCountAPI(Resource):
    """ Endpoint to count assets (devices + gateways). It simply parses the arguments and call
    the functions to count the assets.
    Request arguments (all optional):
    - vendor: for filtering, counts only assets with this vendor.
    - gateway_id: for filtering, only counts this gateway and the devices connected to it.
    - data_collector_id: for filtering, only counts the assest related to this data collector.
    - asset_type: for filtering, only counts this type of devices ("device" or "gateway").
    Returns:
    - A JSON with 4 fields, the names are self-explanatory: n_assets_per_vendor, n_assets_per_gateway, 
        n_assets_per_datacollector, n_assets_per_tags
    """
    @jwt_required
    def get(self):
        try:
            user_identity = get_jwt_identity()
            user = User.find_by_username(user_identity)
            if not user or is_system(user.id):
                return abort(403, error='forbidden access')
            organization_id = user.organization_id

            vendor = request.args.get('vendor', default=None, type=str)
            gateway_id = request.args.get('gateway_id', default=None, type=int)
            data_collector_id = request.args.get('data_collector_id', default=None, type=int)
            asset_type = request.args.get('asset_type', default=None, type=str)

            response = Assets.count_per_tag(
                organization_id,
                vendor=vendor,
                gateway_id=gateway_id,
                data_collector_id=data_collector_id,
                asset_type=asset_type
            )
            return response, 200

        except Exception as e:
            LOG.error(f"Error: {e}")
            return {"message" : "There was an error trying to count assets"}, 400

