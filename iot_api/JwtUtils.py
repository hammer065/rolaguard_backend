import iot_logging
from iot_api.user_api import Error
from iot_api.user_api.model import UserRole
from iot_api.user_api.enums import RoleTypes

import jwt
from flask import abort
from flask_jwt_extended import verify_jwt_in_request, get_jwt_claims
from functools import wraps

log = iot_logging.getLogger(__name__)

def not_system_and_jwt_required(fn):
    @wraps(fn)
    def wrapper(*args,**kwargs):
        verify_jwt_in_request()
        claims = get_jwt_claims()
        try:
            user_roles = [UserRole.find_by_id(user_role_id).role_name for user_role_id in claims.get('user_roles_id')]
        except AttributeError:
            log.error("Couldn't load user roles")
            return abort(403, 'forbiden access')
        if RoleTypes.System.value in user_roles: 
            return abort(403, 'forbidden access')
        else:
            return fn(*args,**kwargs)
    return wrapper