import json
from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from user_api.schemas.asset_importance_schema import AssetImportanceSchema

from iot_api.user_api import db
from iot_api.user_api.model import User
from iot_api.user_api.Utils import is_system
from iot_api.user_api.repository import AssetRepository
from iot_api.user_api import Error


class AssetImportanceAPI(Resource):
    """
    Resource to set (POST) the importance of an asset.
    """

    @jwt_required
    def post(self):
        user = User.find_by_username(get_jwt_identity())
        if not user or is_system(user.id):
            raise Error.Forbidden("User not allowed")
        organization_id = user.organization_id

        body = json.loads(request.data)
        result = AssetImportanceSchema().load(body).data

        importance = result.get('importance')
        if importance not in ['LOW', 'MEDIUM', 'HIGH']:
            raise Exception(f'"{importance}" is not a valid importance value')

        for asset_data in result.get('asset_list'):

            asset = AssetRepository.get_with(
                asset_id=asset_data.get("asset_id"),
                asset_type=asset_data.get("asset_type"),
                organization_id=organization_id
            )
            asset.importance = importance
        db.session.commit()
        
        return {"message": "Assets importance set"}, 200