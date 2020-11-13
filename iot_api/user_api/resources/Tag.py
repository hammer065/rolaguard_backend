from flask import request
from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity
import json

from iot_api.user_api.model import User
from iot_api.user_api.Utils import is_system
from iot_api.user_api.repository import TagRepository
from iot_api.user_api import Error
from iot_api.user_api import db


class TagListAPI(Resource):
    """
    Resource to list all tags (GET) and create new ones (with POST). When 
    creating a new tag, the name and color must be passed as parameters.
    """
    @jwt_required
    def get(self):
        user = User.find_by_username(get_jwt_identity())
        if not user or is_system(user.id):
            raise Error.Forbidden("User not allowed")
        organization_id = user.organization_id

        tag_list = TagRepository.list_all(
            organization_id=organization_id
            )
        return [{
            "id" : tag.id,
            "name" : tag.name,
            "color": tag.color
        } for tag in tag_list], 200

    @jwt_required
    def post(self):
        user = User.find_by_username(get_jwt_identity())
        if not user or is_system(user.id):
            raise Error.Forbidden("User not allowed")
        organization_id = user.organization_id
        
        name = request.args.get('name', type=str)
        color = request.args.get('color', type=str)

        tag_list = TagRepository.list_all(
            organization_id=organization_id
            )
        
        if name in (tag.name for tag in tag_list):
            return [{'code': 'EXISTING_NAME', 'message': 'Existing tag with that name'}], 400

        tag = TagRepository.create(
            name=name,
            color=color,
            organization_id=organization_id
            )
        return {"id": tag.id, "name": tag.name, "color": tag.color}, 200


class TagAPI(Resource):
    """
    Resource to get (GET), update (PATCH) and delete (DELETE) an existing
    tag with the tag_id given in the url. When updating a tag, the new name
    and/or color must be passed as parameters in the request.
    """
    @jwt_required
    def get(self, tag_id):
        user = User.find_by_username(get_jwt_identity())
        if not user or is_system(user.id):
            raise Error.Forbidden("User not allowed")
        organization_id = user.organization_id

        tag = TagRepository.get_with(
            tag_id=tag_id,
            organization_id=organization_id
            )
        return {"id": tag.id, "name": tag.name, "color": tag.color}, 200


    @jwt_required
    def patch(self, tag_id):
        user = User.find_by_username(get_jwt_identity())
        if not user or is_system(user.id):
            raise Error.Forbidden("User not allowed")
        organization_id = user.organization_id
        
        name = request.args.get('name', type=str, default=None)
        color = request.args.get('color', type=str, default=None)


        previous_tag = TagRepository.get_with(tag_id, organization_id)

        tag_list = TagRepository.list_all(
            organization_id=organization_id
            )
        
        if name in (tag.name for tag in tag_list) and name != previous_tag.name:
            return [{'code': 'EXISTING_NAME', 'message': 'Existing tag with that name'}], 400

        TagRepository.update(
            tag_id=tag_id,
            name=name,
            color=color,
            organization_id=organization_id)
        return {"message": "Tag updated"}, 200

    @jwt_required
    def delete(self, tag_id):
        user = User.find_by_username(get_jwt_identity())
        if not user or is_system(user.id):
            raise Error.Forbidden("User not allowed")
        organization_id = user.organization_id

        TagRepository.delete(
            tag_id=tag_id,
            organization_id=organization_id
            )
        return {"message": "Tag deleted"}, 200



class TagAssetsAPI(Resource):
    """
    Resource to tag (POST) and untag (DELETE) an asset. The tag_id is defined in
    the URL, and the asset_id and asset_type are given as parameters in the
    request.
    """
    parser = reqparse.RequestParser()
    parser.add_argument('asset_list', required=True, action='append')

    @jwt_required
    def post(self, tag_id):
        user = User.find_by_username(get_jwt_identity())
        if not user or is_system(user.id):
            return abort(403, error='forbidden access')
        organization_id = user.organization_id

        asset_list = TagAssetsAPI.parser.parse_args()["asset_list"]

        for asset in asset_list:
            asset = json.loads(asset.replace("\'", "\""))
            TagRepository.tag_asset(
                tag_id=tag_id,
                asset_id=int(asset["asset_id"]),
                asset_type=asset["asset_type"],
                organization_id=organization_id,
                commit=False
                )
        db.session.commit()
        return {"message": "Assets tagged"}, 200
    
    @jwt_required
    def delete(self, tag_id):
        user = User.find_by_username(get_jwt_identity())
        if not user or is_system(user.id):
            return abort(403, error='forbidden access')
        organization_id = user.organization_id

        asset_list = TagAssetsAPI.parser.parse_args()["asset_list"]

        for asset in asset_list:
            asset = json.loads(asset.replace("\'", "\""))
            TagRepository.untag_asset(
                tag_id=tag_id,
                asset_id=int(asset["asset_id"]),
                asset_type=asset["asset_type"],
                organization_id=organization_id,
                commit=False
            )
        db.session.commit()
        return {"message": "Asset untagged"}, 200