import json
from flask import request
from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity

from iot_api.user_api import db
from iot_api.user_api.model import User
from iot_api.user_api.Utils import is_system
from iot_api.user_api.repository import AssetRepository
from iot_api.user_api import Error


class AssetImportanceAPI(Resource):
    """
    Resource to set (POST) the importance of an asset.
    """
    parser = reqparse.RequestParser()
    parser.add_argument('asset_list', required=True, action='append')
    parser.add_argument('importance', required=True)

    @jwt_required
    def post(self):
        user = User.find_by_username(get_jwt_identity())
        if not user or is_system(user.id):
            raise Error.Forbidden("User not allowed")
        organization_id = user.organization_id

        args = self.parser.parse_args()
        asset_list = args["asset_list"]
        importance = args["importance"]

        if importance not in ['LOW', 'MEDIUM', 'HIGH']:
            raise Exception(f'"{importance}" is not a valid importance value')

        for asset_id in asset_list:
            asset_id = json.loads(asset_id.replace("\'", "\""))
            asset = AssetRepository.get_with(
                asset_id=int(asset_id["asset_id"]),
                asset_type=asset_id["asset_type"],
                organization_id=organization_id
            )
            asset.importance = importance
        db.session.commit()
        return {"message": "Assets importance set"}, 200