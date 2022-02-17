import json
from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from user_api.schemas.asset_hiding_schema import AssetHidingSchema

from iot_api.user_api import db
from iot_api.user_api.model import DeviceHiding, GatewayHiding, User
from iot_api.user_api.Utils import is_system
from iot_api.user_api import Error

class AssetHidingAPI(Resource):
    """
    Resource to set (POST) the hiding of an asset.
    """

    @jwt_required
    def post(self):
        user = User.find_by_username(get_jwt_identity())
        if not user or is_system(user.id):
            raise Error.Forbidden("User not allowed")

        body = json.loads(request.data)
        result = AssetHidingSchema().load(body).data

        hidden = result.get('hidden')
        for asset in result.get('asset_list'):
            
            asset_hiding = None
            if(asset.get('asset_type')=='device'):
                asset_hiding = DeviceHiding.find(device_id=asset.get('asset_id'),user_id=user.id)
                if not asset_hiding:
                    asset_hiding = DeviceHiding(device_id=asset.get('asset_id'),user_id=user.id)
            else:
                asset_hiding = GatewayHiding.find(gateway_id=asset.get('asset_id'),user_id=user.id)
                if not asset_hiding:
                    asset_hiding = GatewayHiding(gateway_id=asset.get('asset_id'),user_id=user.id)
            asset_hiding.hidden = hidden 
            asset_hiding.save()
        db.session.commit()
        return {"message": "Assets hiding set"}, 200
