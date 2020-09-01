import calendar
import dateutil.parser as dp
from flask import request, abort
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_claims, get_jwt_identity

import iot_logging
log = iot_logging.getLogger(__name__)

from iot_api.user_api.model import User, Alert, Quarantine, GatewayToDevice, AlertType
from iot_api.user_api.Utils import is_system
from iot_api.user_api.JwtUtils import admin_regular_allowed
from iot_api.user_api.repository import AssetRepository, TagRepository

class AssetInformationAPI(Resource):
    """ Endpoint to get information about an asset of a given type
    Request parameters:
        - asset_type: type of requested asset (can be device or gateway).
        - asset_id: database id of the asset
    Returns:
        - JSON with requested asset. See Device/Gateway model's to_asset_json method for further details
    """
    @admin_regular_allowed
    def get(self, asset_type, asset_id):
        organization_id = get_jwt_claims().get('organization_id')
        asset = AssetRepository.get_with(asset_id, asset_type,  organization_id)
        response = asset.to_asset_json()
        response['tags'] = [{
                "id": tag.id,
                "name": tag.name,
                "color": tag.color
            } for tag in TagRepository.list_asset_tags(asset_id, asset_type, organization_id)
        ]
        return response, 200
       
class AssetAlertsAPI(Resource):
    """ Endpoint to list and filter alerts from a given asset
    Request parameters:
        - asset_type: type of asset (can be device or gateway).
        - asset_id: database id of the asset
        - created_at[gte]: for date filtering, if specified, returns alerts created AFTER this date.
            if is not specified, no date filtering is applied
        - created_at[lte]: for date filtering, if specified, returns alerts created BEFORE this date
            if is not specified, no date filtering is applied
        - type: include alerts of types specified in this list
            if is not specified, no type filtering is applied
        - resolved: filter by status of alert's resolution. 
            if is not specified, no filter is applied
        - risk: include only alerts whose associated risk's enumerated in this list
            if is not specified, no risk filtering is applied
        - order_by: ordering criteria, list composed by
            order_field: database field 
            order_direction: either ASC or DESC
            if is not specified, default behaviour is to order by date (created_at field), newest first (DESC)
        - page: requested page number for pagination, defaults to 1 (first page)
        - size: results per page, defaults to 20
    Returns:
        - paginated list of alerts. see Alert model's to_json method to further details
    """
    @admin_regular_allowed
    def get(self, asset_type, asset_id):
        organization_id = get_jwt_claims().get("organization_id")
        since = request.args.get('created_at[gte]')
        until = request.args.get('created_at[lte]')
        types = request.args.getlist('type[]')
        resolved = request.args.get('resolved')
        risks = request.args.getlist('risk[]')
        order_by = request.args.getlist('order_by[]')
        page = request.args.get('page', default=1, type=int)
        size = request.args.get('size', default=20, type=int)
        
        if since:
            try:
                since = dp.parse(since)
            except Exception:
                raise Error.BadRequest('no valid created_at[gte] value')

        if until:
            try:
                until = dp.parse(until)
            except Exception:
                raise Error.BadRequest('no valid created_at[lte] value')

        if since and until and since > until:
            raise Error.BadRequest('since value must be before to until value')

        if not order_by or len(order_by) < 2 or order_by[1] not in ('ASC', 'DESC'):
            order_by = None

        if page:
            try:
                page = int(page)
            except Exception:
                return Error.BadRequest('no valid page value')

        if size:
            try:
                size = int(size)
            except Exception:
                return Error.BadRequest('no valid size value')

        if resolved:
            resolved = resolved == 'true'

        asset = AssetRepository.get_with(asset_id, asset_type, organization_id)

        if asset_type == 'device': 
            results = Alert.find_by_device_id(
                device_id=asset.id,
                organization_id=organization_id,
                since=since,
                until=until,
                types=types,
                resolved=resolved,
                risks=risks,
                order_by=order_by,
                page=page,
                size=size
            )
        else:
            results = Alert.find_by_gateway_id(
                gateway_id=asset.id,
                organization_id=organization_id,
                since=since,
                until=until,
                types=types,
                resolved=resolved,
                risks=risks,
                order_by=order_by,
                page=page,
                size=size
            )

        alerts = [alert.to_json() for alert in results.items]
        response = {
            'alerts' : alerts,
            'total_pages': results.pages,
            'total_items': results.total
        }
        return response, 200

class AssetIssuesAPI(Resource):
    """ Endpoint to list and filter quarantine entries from a given asset
    Request parameters:
        - asset_type: type of asset (can be device or gateway).
        - asset_id: database id of the asset
        - created_at[gte]: for date filtering, if specified, returns alerts created AFTER this date.
            if is not specified, no date filtering is applied
        - created_at[lte]: for date filtering, if specified, returns alerts created BEFORE this date
            if is not specified, no date filtering is applied
        - type: include alerts of types specified in this list
            if is not specified, no type filtering is applied
        - resolved: filter by status of alert's resolution. 
            if is not specified, no filter is applied
        - risk: include only alerts whose associated risk's enumerated in this list
            if is not specified, no risk filtering is applied
        - order_by: ordering criteria, list composed by
            order_field: database field 
            order_direction: either ASC or DESC
            if is not specified, default behaviour is to order by date (created_at field), newest first (DESC)
        - page: requested page number for pagination, defaults to 1 (first page)
        - size: results per page, defaults to 20
    Returns:
        - paginated list of issues. see Quarantine model's to_json method to further details
    """
    @admin_regular_allowed
    def get(self, asset_type, asset_id):
        organization_id = get_jwt_claims().get("organization_id")
        since = request.args.get('created_at[gte]')
        until = request.args.get('created_at[lte]')
        alert_types = request.args.getlist('type[]')
        risks = request.args.getlist('risk[]')
        order_by = request.args.getlist('order_by[]')
        page = request.args.get('page', default=1, type=int)
        size = request.args.get('size', default=20, type=int)

        if since:
            try:
                since = dp.parse(since)
            except Exception:
                raise Error.BadRequest('no valid created_at[gte] value')

        if until:
            try:
                until = dp.parse(until)
            except Exception:
                raise Error.BadRequest('no valid created_at[lte] value')

        if since and until and since > until:
            raise Error.BadRequest('since value must be before to until value')

        if not order_by or len(order_by) < 2 or order_by[1] not in ('ASC', 'DESC'):
            order_by = None

        if page:
            try:
                page = int(page)
            except Exception:
                return Error.BadRequest('no valid page value')

        if size:
            try:
                size = int(size)
            except Exception:
                return Error.BadRequest('no valid size value')

        asset = AssetRepository.get_with(asset_id, asset_type, organization_id)
        
        if asset_type == 'device': # for a device, return all the issues that this device has created
            results = Quarantine.find(
                organization_id=organization_id,
                since=since,
                until=until,
                alert_types=[AlertType.find_one(alert_type_code).id for alert_type_code in alert_types],
                devices=[asset.id],
                risks=risks,
                data_collectors=None,
                order_by=order_by,
                page=page,
                size=size
            ) 
        else: # for a gateway, return all the issues that the devices connected to this gateway have created
            results = Quarantine.find(
                organization_id=organization_id,
                since=since,
                until=until,
                alert_types=[AlertType.find_one(alert_type_code).id for alert_type_code in alert_types],
                devices=[entry.device_id for entry in GatewayToDevice.find_by_gateway_id(asset.id)],
                risks=risks,
                data_collectors=None,
                order_by=order_by,
                page=page,
                size=size
            )

        issues = [issue.to_list_json() for issue in results.items]
        response = {
            'issues' : issues,
            'total_pages': results.pages,
            'total_items': results.total
        }
        return response,200


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
        user = User.find_by_username(get_jwt_identity())
        if not user or is_system(user.id):
            return abort(403, error='forbidden access')

        organization_id = user.organization_id
        page = request.args.get('page', default=1, type=int)
        size = request.args.get('size', default=20, type=int)

        results = AssetRepository.list_all(
            organization_id=organization_id,
            page=page, size=size,
            vendors=request.args.getlist('vendors[]'),
            gateway_ids=request.args.getlist('gateway_ids[]'),
            data_collector_ids=request.args.getlist('data_collector_ids[]'),
            tag_ids=request.args.getlist('tag_ids[]'),
            asset_type=request.args.get('asset_type', type=str)
        )

        devices = [{
            'id' : dev.id,
            'hex_id' : dev.hex_id,
            'type' : dev.type,
            'name' : dev.name,
            'data_collector' : dev.data_collector,
            'vendor' : dev.vendor,
            'app_name' : dev.app_name,
            'join_eui' : dev.join_eui,
            'importance' : dev.importance.value,
            'connected' : dev.connected,
            'last_activity' : calendar.timegm(dev.last_activity.timetuple()),
            'location' : {'latitude' : dev.location_latitude,
                          'longitude': dev.location_longitude},
            'tags' : [{"id" : tag.id,
                        "name" : tag.name,
                        "color" : tag.color}
                        for tag in TagRepository.list_asset_tags(dev.id, dev.type.lower(), organization_id)]
        } for dev in results.items]
        response = {
            'assets' : devices,
            'total_pages': results.pages,
            'total_items': results.total
        }
        return response, 200


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
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)
        if not user or is_system(user.id):
            return abort(403, error='forbidden access')
        organization_id = user.organization_id

        response = AssetRepository.count_per_vendor(
            organization_id = organization_id,
            vendors = request.args.getlist('vendors[]'),
            gateway_ids = request.args.getlist('gateway_ids[]'),
            data_collector_ids = request.args.getlist('data_collector_ids[]'),
            tag_ids = request.args.getlist('tag_ids[]'),
            asset_type = request.args.get('asset_type', default=None, type=str)
        )
        return response, 200

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
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)
        if not user or is_system(user.id):
            return abort(403, error='forbidden access')
        organization_id = user.organization_id

        response = AssetRepository.count_per_gateway(
            organization_id = organization_id,
            vendors = request.args.getlist('vendors[]'),
            gateway_ids = request.args.getlist('gateway_ids[]'),
            data_collector_ids = request.args.getlist('data_collector_ids[]'),
            tag_ids = request.args.getlist('tag_ids[]'),
            asset_type = request.args.get('asset_type', default=None, type=str)
        )
        return response, 200
            

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
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)
        if not user or is_system(user.id):
            return abort(403, error='forbidden access')
        organization_id = user.organization_id

        response = AssetRepository.count_per_datacollector(
            organization_id = organization_id,
            vendors = request.args.getlist('vendors[]'),
            gateway_ids = request.args.getlist('gateway_ids[]'),
            data_collector_ids = request.args.getlist('data_collector_ids[]'),
            tag_ids = request.args.getlist('tag_ids[]'),
            asset_type = request.args.get('asset_type', default=None, type=str)
        )
        return response, 200


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
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)
        if not user or is_system(user.id):
            return abort(403, error='forbidden access')
        organization_id = user.organization_id

        counts = AssetRepository.count_per_tag(
            organization_id = organization_id,
            vendors = request.args.getlist('vendors[]'),
            gateway_ids = request.args.getlist('gateway_ids[]'),
            data_collector_ids = request.args.getlist('data_collector_ids[]'),
            tag_ids = request.args.getlist('tag_ids[]'),
            asset_type = request.args.get('asset_type', default=None, type=str)
        )
        response = [
            {
                'id' : tag_id,
                'name' : tag['name'],
                'color' : tag['color'],
                'count' : tag['count']
                }
             for tag_id, tag in counts.items()
             ]
        return response, 200
