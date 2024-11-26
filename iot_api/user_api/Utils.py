from iot_api.user_api.model import UserRole, UserToUserRole
from iot_api.user_api.enums import RoleTypes

import re
from validators.ip_address import ipv4, ipv6
from validators.domain import domain

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


_port_regex = re.compile(r"^\:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})$")
_simple_hostname_regex = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$")


def validators_hostname(
    value: str,
    may_have_port: bool = True,
    skip_ip_addr: bool = False,
    maybe_simple: bool = True,
    rfc_1034: bool = False,
    rfc_2782: bool = False,
):
    """Return whether or not given value is a valid hostname.

    Examples:
        >>> hostname("ubuntu-pc:443")
        # Output: True
        >>> hostname("this-pc")
        # Output: True
        >>> hostname("xn----gtbspbbmkef.xn--p1ai:65535")
        # Output: True
        >>> hostname("_example.com")
        # Output: True
        >>> hostname("123.5.77.88:31000")
        # Output: True
        >>> hostname("12.12.12.12")
        # Output: True
        >>> hostname("[::1]:22")
        # Output: True
        >>> hostname("dead:beef:0:0:0:0000:42:1")
        # Output: True
        >>> hostname("[0:0:0:0:0:ffff:1.2.3.4]:-65538")
        # Output: ValidationFailure(func=hostname, ...)
        >>> hostname("[0:&:b:c:@:e:f::]:9999")
        # Output: ValidationFailure(func=hostname, ...)

    Args:
        value:
            Hostname string to validate.
        may_have_port:
            Hostname string may contain port number.
        skip_ip_addr:
            When hostname string cannot be an IP address.
        maybe_simple:
            Hostname string maybe only hyphens and alpha-numerals.
        rfc_1034:
            Allow trailing dot in domain/host name.
            Ref: [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034).
        rfc_2782:
            Domain/Host name is of type service record.
            Ref: [RFC 2782](https://www.rfc-editor.org/rfc/rfc2782).

    Returns:
        (Literal[True]):
            If `value` is a valid hostname.
        (ValidationFailure):
            If `value` is an invalid hostname.

    > *New in version 0.21.0*.
    """
    if may_have_port:
        if value.count("]:") == 1 and not skip_ip_addr:
            host_seg, port_seg = value.rsplit(":", 1)
            return _port_regex.match(f":{port_seg}") and ipv6(
                host_seg.lstrip("[").rstrip("]"), cidr=False
            )
        if value.count(":") == 1:
            host_seg, port_seg = value.rsplit(":", 1)
            return _port_regex.match(f":{port_seg}") and (
                (_simple_hostname_regex.match(host_seg) if maybe_simple else False)
                or domain(host_seg, rfc_1034=rfc_1034, rfc_2782=rfc_2782)
                or (False if skip_ip_addr else ipv4(host_seg, cidr=False))
            )

    return (
        (_simple_hostname_regex.match(value) if maybe_simple else False)
        or domain(value, rfc_1034=rfc_1034, rfc_2782=rfc_2782)
        or (False if skip_ip_addr else ipv4(value, cidr=False))
        or (False if skip_ip_addr else ipv6(value, cidr=False))
    )

