import iot_logging
LOG = iot_logging.getLogger(__name__)

from sqlalchemy import not_

from iot_api.user_api import db
from iot_api.user_api.models import Tag, NotificationAssetTag
from iot_api.user_api import Error
from iot_api.user_api.repository import TagRepository

def get_asset_tags(user_id):
    """
    Get the list of tags that a device must have, according to this user's
    NotificationPreferences, in order to notify him when an alert event occurs.
    """
    result = db.session.query(Tag).filter(
        NotificationAssetTag.user_id == user_id,
        NotificationAssetTag.tag_id == Tag.id
        ).all()
    return result if result else []


def upsert_asset_tags(user_id, tag_id_list, commit=True):
    """
    Insert rows in the DB to relate this user with every tag in
    tag_id_list, considering that they may be already related.
    """
    db_entries = NotificationAssetTag.find_all_with(user_id = user_id)
    already_in_db = set([row.tag_id for row in db_entries])
    for tag_id in tag_id_list:
        if tag_id not in already_in_db:
            db.session.add(NotificationAssetTag(user_id = user_id, tag_id = tag_id))
    if commit:
        db.session.commit()

def set_asset_tags(user_id, tag_id_list, commit=True):
    """
    1- Check that each tag in tag_id_list belongs to the user's organization
    2- Delete every entry that relates the user with tags that are not present in tag_list.
    3- Upsert tags for this user
    """
    if not TagRepository.are_from_user_organization(tag_id_list, user_id):
        raise Error.Unauthorized("Every asset_tag for a user's notification preferences must belong to his organization")

    db.session.query(NotificationAssetTag).filter(
        NotificationAssetTag.user_id == user_id,
        not_(NotificationAssetTag.tag_id.in_(tag_id_list))
        ).delete(synchronize_session = False)

    upsert_asset_tags(user_id, tag_id_list, commit)
    
