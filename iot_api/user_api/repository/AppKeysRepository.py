import iot_logging
log = iot_logging.getLogger(__name__)

from iot_api.user_api import db
from iot_api.user_api.models import AppKey
from iot_api.user_api import Error

MAX_PER_ORGANIZATION = 500

def count_with(organization_id):
    """ Count all app keys of an organization """
    return db.session.query(AppKey).filter(AppKey.organization_id==organization_id).count()

def get_with(organization_id, keys_list=None):
    """ List app keys of an organization.
    Parameters:
        - organization_id: which organization,
        - keys_list: for filtering, list only app keys that are present in this list
    """
    qry = db.session.query(AppKey).filter(AppKey.organization_id==organization_id)
    if keys_list:
        qry = qry.filter(AppKey.key.in_(keys_list))
    result = qry.all()
    return result if result else []

def create(keys_list, organization_id): 
    """
    Create a new app_key for every key in keys_list that is
    not already part of this organizantion's set of keys.
    """
    global MAX_PER_ORGANIZATION

    already_in_db = set(row.key for row in get_with(
        organization_id = organization_id,
        keys_list = keys_list))
    total = count_with(organization_id = organization_id)
    created = 0

    for key in keys_list:
        if key not in already_in_db:
            db.session.add(AppKey(key = key, organization_id = organization_id))
            already_in_db.add(key)
            created = created + 1

    if total + created > MAX_PER_ORGANIZATION:
        db.session.rollback()
        raise Error.Forbidden("Creating these app keys would exceed the limit per organization")

    db.session.commit()
    return created

def delete(keys_list, organization_id):
    """
    Delete every app_key present in keys_list that is
    part of this organizantion's set of keys.
    """
    qry = db.session.query(AppKey).filter(
        AppKey.organization_id == organization_id,
        AppKey.key.in_(keys_list))
    deleted = qry.count()
    qry.delete(synchronize_session = False)
    db.session.commit()
    return deleted