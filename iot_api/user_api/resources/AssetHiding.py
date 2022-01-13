import json
from flask import request
from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity

from iot_api.user_api import db
from iot_api.user_api.model import DeviceHiding, GatewayHiding, User
from iot_api.user_api.Utils import is_system
from iot_api.user_api import Error

class AssetHidingAPI(Resource):
    """
    Resource to set (POST) the hiding of an asset.
    """
    parser = reqparse.RequestParser()
    parser.add_argument('asset_list', required=True, action='append')
    parser.add_argument('hidden', required=True)

    @jwt_required
    def post(self):
        user = User.find_by_username(get_jwt_identity())
        if not user or is_system(user.id):
            raise Error.Forbidden("User not allowed")

        args = self.parser.parse_args()
        asset_list = args["asset_list"]
        hidden = args["hidden"]

        for asset_id in asset_list:
            asset_id = json.loads(asset_id.replace("\'", "\""))    
            
            asset_hiding = None
            if(str(asset_id["asset_type"])=='device'):
                asset_hiding = DeviceHiding.find(device_id=int(asset_id["asset_id"]),user_id=user.id)
                if not asset_hiding:
                    asset_hiding = DeviceHiding(device_id=int(asset_id['asset_id']),user_id=user.id)
            else:
                asset_hiding = GatewayHiding.find(gateway_id=int(asset_id["asset_id"]),user_id=user.id)
                if not asset_hiding:
                    asset_hiding = GatewayHiding(user_id=user.id,gateway_id=int(asset_id['asset_id']))
            asset_hiding.hidden = hidden == 'True' 
            asset_hiding.save()
        db.session.commit()
        return {"message": "Assets hiding set"}, 200
