from flask import request, abort
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity

import iot_logging
log = iot_logging.getLogger(__name__)

from iot_api.user_api.model import User
from iot_api.user_api.Utils import is_system
from iot_api.user_api.repository import TagRepository


class TagListAPI(Resource):
    """
    Resource to list all tags (GET) and create new ones (with POST). When 
    creating a new tag, the name and color must be passed as parameters.
    """
    @jwt_required
    def get(self):
        try:
            user = User.find_by_username(get_jwt_identity())
            if not user or is_system(user.id):
                return abort(403, error='forbidden access')
            organization_id = user.organization_id

            tag_list = TagRepository.list_all(
                organization_id=organization_id
                )
            return [{
                "id" : tag.id,
                "name" : tag.name,
                "color": tag.color
            } for tag in tag_list], 200
        except Exception as e:
            log.error(f"Error: {e}")
            return {"message" : "There was an error trying to get a tag"}, 500

    @jwt_required
    def post(self):
        try:
            user = User.find_by_username(get_jwt_identity())
            if not user or is_system(user.id):
                return abort(403, error='forbidden access')
            organization_id = user.organization_id
            
            name = request.args.get('name', type=str)
            color = request.args.get('color', type=str)
            TagRepository.create(
                name=name,
                color=color,
                organization_id=organization_id
                )
            return {"message": "Tag created"}, 200
        except Exception as e:
            log.error(f"Error: {e}")
            return {"message" : "There was an error trying to create a tag"}, 500


class TagAPI(Resource):
    """
    Resource to get (GET), update (PATCH) and delete (DELETE) an existing
    tag with the tag_id given in the url. When updating a tag, the new name
    and/or color must be passed as parameters in the request.
    """
    @jwt_required
    def get(self, tag_id):
        try:
            user = User.find_by_username(get_jwt_identity())
            if not user or is_system(user.id):
                return abort(403, error='forbidden access')
            organization_id = user.organization_id

            tag = TagRepository.get_with(
                tag_id=tag_id,
                organization_id=organization_id
                )
            return {"id": tag.id, "name": tag.name, "color": tag.color}, 200
        except Exception as e:
            log.error(f"Error: {e}")
            return {"message" : "There was an error trying to get a tag"}, 500


    @jwt_required
    def patch(self, tag_id):
        try:
            user = User.find_by_username(get_jwt_identity())
            if not user or is_system(user.id):
                return abort(403, error='forbidden access')
            organization_id = user.organization_id
            
            name = request.args.get('name', type=str, default=None)
            color = request.args.get('color', type=str, default=None)
            TagRepository.update(
                tag_id=tag_id,
                name=name,
                color=color,
                organization_id=organization_id)
            return {"message": "Tag updated"}, 200
        except Exception as e:
            log.error(f"Error: {e}")
            return {"message" : "There was an error trying to create a tag"}, 500

    @jwt_required
    def delete(self, tag_id):
        try:
            user = User.find_by_username(get_jwt_identity())
            if not user or is_system(user.id):
                return abort(403, error='forbidden access')
            organization_id = user.organization_id

            TagRepository.delete(
                tag_id=tag_id,
                organization_id=organization_id
                )
            return {"message": "Tag deleted"}, 200
        except Exception as e:
            log.error(f"Error: {e}")
            return {"message" : "There was an error trying to delete a tag"}, 500



class TagAssetsAPI(Resource):
    """
    Resource to tag (POST) and untag (DELETE) an asset. The tag_id is defined in
    the URL, and the asset_id and asset_type are given as parameters in the
    request.
    """
    @jwt_required
    def post(self, tag_id):
        try:
            user = User.find_by_username(get_jwt_identity())
            if not user or is_system(user.id):
                return abort(403, error='forbidden access')
            organization_id = user.organization_id

            asset_id = request.args.get('asset_id', type=int)
            asset_type = request.args.get('asset_type', type=str)
            TagRepository.tag_asset(
                tag_id=tag_id,
                asset_id=asset_id,
                asset_type=asset_type,
                organization_id=organization_id
                )
            return {"message": "Asset tagged"}, 200
        except Exception as e:
            log.error(f"Error: {e}")
            return {"message" : "There was an error trying to tag assets"}, 500

    @jwt_required
    def delete(self, tag_id):
        try:
            user = User.find_by_username(get_jwt_identity())
            if not user or is_system(user.id):
                return abort(403, error='forbidden access')
            organization_id = user.organization_id

            asset_id = request.args.get('asset_id', type=int)
            asset_type = request.args.get('asset_type', type=str)
            TagRepository.untag_asset(
                tag_id=tag_id,
                asset_id=asset_id,
                asset_type=asset_type,
                organization_id=organization_id
            )
            return {"message": "Asset untagged"}, 200
        except Exception as e:
            log.error(f"Error: {e}")
            return {"message" : "There was an error trying to untag assets"}, 500