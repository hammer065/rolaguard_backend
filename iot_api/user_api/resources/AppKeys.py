from flask import request
from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity
import json, string

from iot_api.user_api.model import User
from iot_api.user_api.Utils import is_system
from iot_api.user_api.repository import AppKeysRepository
from iot_api.user_api.schemas.app_keys_schema import AppKeysSchema
from iot_api.user_api import Error

from iot_api.user_api.repository.AppKeysRepository import MAX_PER_ORGANIZATION

import iot_logging
log = iot_logging.getLogger(__name__)

class AppKeysAPI(Resource):
    """
    Resource to list all app keys (GET), create new ones (with POST) and
    delete some of the existing ones (with DELETE).
    For POST and DELETE, the body must be a non-emtpy list of keys, where
    every key contains only hex digits.
    """
    @jwt_required
    def get(self):
        user = User.find_by_username(get_jwt_identity())
        if not user or is_system(user.id):
            raise Error.Forbidden("User not allowed")
        organization_id = user.organization_id

        app_keys = AppKeysRepository.get_with(organization_id = organization_id)

        return {
            "limit": MAX_PER_ORGANIZATION,
            "count": len(app_keys),
            "keys": [{
                "id": app_key.id,
                "key": app_key.key,
                "organization_id": app_key.organization_id
            } for app_key in app_keys]
        }, 200
        
    @jwt_required
    def post(self):
        user = User.find_by_username(get_jwt_identity())
        if not user or is_system(user.id):
            raise Error.Forbidden("User not allowed")
        organization_id = user.organization_id
        
        body = json.loads(request.data)
        parsed_result = AppKeysSchema().load(body).data
        app_keys = parsed_result.get('keys')
        if app_keys is None:
            raise Error.BadRequest(f"AppKeysAPI POST request body must contain a non-empty list of keys with at most {MAX_PER_ORGANIZATION} keys")

        total = len(app_keys)
        app_keys = list(set(app_keys))
        not_duplicated = len(app_keys)
        validate_keys(app_keys)

        created = AppKeysRepository.create(
            keys_list = app_keys,
            organization_id = organization_id)
        return {"message": f"{created} app keys created, {total-not_duplicated} were duplicated and {not_duplicated-created} already existed"}, 200

    @jwt_required
    def delete(self):
        user = User.find_by_username(get_jwt_identity())
        if not user or is_system(user.id):
            raise Error.Forbidden("User not allowed")
        organization_id = user.organization_id

        body = json.loads(request.data)
        parsed_result = AppKeysSchema().load(body).data
        app_keys = parsed_result.get('keys')
        if app_keys is None:
            raise Error.BadRequest(f"AppKeysAPI POST request body must contain a non-empty list of keys with at most {MAX_PER_ORGANIZATION} keys")

        total = len(app_keys)
        app_keys = list(set(app_keys))
        not_duplicated = len(app_keys)
        validate_keys(app_keys)

        deleted = AppKeysRepository.delete(
            keys_list = app_keys,
            organization_id = organization_id)        
        return {"message": f"{deleted} app keys deleted, {total-not_duplicated} were duplicated and {not_duplicated-deleted} were not present in user's organization"}, 200

def validate_keys(app_keys):
    """
    Helper function to validate that every key in a
    list of keys is a hex string of length 32
    """
    hex_digits = set(list(string.hexdigits))
    for key in app_keys:
        if len(key) != 32:
            raise Error.BadRequest(f"Every key must have 32 characters, but received one with length {len(key)}")
        for char in key:
            if char not in hex_digits:
                raise Error.BadRequest(f"Every key must contain only hex digits, but one had a \"{char}\"")
