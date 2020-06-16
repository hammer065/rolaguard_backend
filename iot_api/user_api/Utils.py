from iot_api.user_api.model import UserRole, UserToUserRole
from iot_api.user_api.enums import RoleTypes

def is_admin_user(user_id):
    """ verify if specified username belongs to user with role 'User_Admin' """
    role = UserRole.find_by_role_name(RoleTypes.User_Admin.value)
    if not role:
        return False
    role_id = role.id
    if not role_id:
        return False
    if UserToUserRole.find_by_user_id_and_user_role_id(user_id, role_id):
        return True
    else:
        return False

def is_regular_user(user_id):
    """ verify if specified username belongs to user with role 'Regular_User' """
    role = UserRole.find_by_role_name(RoleTypes.Regular_User.value)
    if not role:
        return False
    role_id = role.id
    if not role_id:
        return False
    if UserToUserRole.find_by_user_id_and_user_role_id(user_id, role_id):
        return True
    else:
        return False




# verify if specified username is system
def is_system(user_id):
    role = UserRole.find_by_role_name(RoleTypes.System.value)
    if not role:
        return False
    role_id = role.id
    if not role_id:
        return False
    if not role_id:
        return False
    if UserToUserRole.find_by_user_id_and_user_role_id(user_id, role_id):
        return True
    else:
        return False