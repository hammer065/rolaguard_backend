import iot_logging
log = iot_logging.getLogger(__name__)

from sqlalchemy import func, or_, distinct
from sqlalchemy.sql import select, expression, text

from iot_api.user_api import db
from iot_api.user_api.models import Tag, DeviceToTag, GatewayToTag
from iot_api.user_api.model import Device, Gateway, User
from iot_api.user_api.repository import DeviceRepository, GatewayRepository
from iot_api.user_api import Error


def list_all(organization_id):
    """
    List all tags of an organization.
    """
    result = db.session.query(Tag).filter(Tag.organization_id==organization_id).all()
    return result if result else []

def create(name, color, organization_id): 
    """
    Create a new tag with the given name, color and organization_id, returns the
    id of the new tag.
    """
    tag = Tag(name=name, color=color, organization_id=organization_id)
    db.session.add(tag)
    db.session.commit()
    return tag

def get_with(tag_id, organization_id):
    """
    Get a tag with the given tag_id and organization_id. If not exists raise an
    exception.
    """
    tag = db.session.query(Tag).filter(Tag.id==tag_id, Tag.organization_id==organization_id).first()
    if not tag:
        raise Error.UnprocessableEntity(f"The tag {tag_id} with organization {organization_id} was not found")
    return tag

def update(tag_id, name, color, organization_id):
    """
    Update the name and/or color of the tag with the given tag_id and
    organization_id. If the tag does no exists, raise an exception.
    """
    tag = get_with(tag_id, organization_id)
    if name: tag.name = name
    if color: tag.color = color
    db.session.commit()

def delete(tag_id, organization_id):
    """ 
    Delete the tag with the given tag_id and organization_id. If not found,
    raise and exception.
    """
    tag = get_with(tag_id, organization_id)
    db.session.delete(tag)
    db.session.commit()

def is_from_organization(tag_id, organization_id):
    """
    Return a boolean indicating if the tag belongs to this organization.
    """
    return db.session.query(Tag.query.filter(
        Tag.id == tag_id,
        Tag.organization_id == organization_id
    ).exists()).scalar()

def is_tagged(tag_id, asset_id, asset_type):
    if asset_type=="device":
        return db.session.query(DeviceToTag.query.\
            filter(DeviceToTag.tag_id == tag_id).\
            filter(DeviceToTag.device_id == asset_id).exists()).scalar()
    elif asset_type=="gateway":
        return db.session.query(GatewayToTag.query.\
            filter(GatewayToTag.tag_id == tag_id).\
            filter(GatewayToTag.gateway_id == asset_id).exists()).scalar()
    else:
        raise Error.BadRequest(f"Invalid asset_type: {asset_type}")

def are_from_user_organization(tag_id_list, user_id):
    """
    Return a boolean indicating if every tag in tag_id_list belongs to the user's organization
    """
    return db.session.query(Tag).filter(
        User.id == user_id,
        Tag.organization_id == User.organization_id,
        Tag.id.in_(tag_id_list)
        ).count() == len(tag_id_list)


def tag_asset(tag_id, asset_id, asset_type, organization_id, commit=True):
    """
    Tag the asset with the given asset_type ("device" or "gateway") and asset_id
    (device_id or gateway_id) with the tag with tag_id and organization_id.
    """
    if not is_from_organization(tag_id, organization_id):
        raise Error.Forbidden("Trying to use a tag from other organization.")
    if is_tagged(tag_id, asset_id, asset_type): return

    if asset_type=="device":
        if not DeviceRepository.is_from_organization(asset_id, organization_id):
            raise Error.Forbidden("Trying to tag a device from other organization")
        asset_tag = DeviceToTag(tag_id=tag_id, device_id=asset_id)
        db.session.add(asset_tag)
    elif asset_type=="gateway":
        if not GatewayRepository.is_from_organization(asset_id, organization_id):
            raise Error.Forbidden("Trying to tag a gateway from other organization")
        asset_tag = GatewayToTag(tag_id=tag_id, gateway_id=asset_id)
        db.session.add(asset_tag)
    else:
        raise Error.BadRequest(f"Invalid asset_type: {asset_type}")
    if commit: db.session.commit()

def untag_asset(tag_id, asset_id, asset_type, organization_id, commit=True):
    """
    Remove the tag with the tag_id and organization_id from the asset with the
    given asset_type ("device" or "gateway") and asset_id (device_id or
    gateway_id).
    """
    if not is_from_organization(tag_id, organization_id):
        raise Error.Forbidden("Trying to delete a tag from other organization.")

    if asset_type=="device":
        if not DeviceRepository.is_from_organization(asset_id, organization_id):
            raise Error.Forbidden("Trying to untag a device from other organization")
        asset_tag = db.session.query(DeviceToTag).\
            filter(DeviceToTag.tag_id==tag_id, DeviceToTag.device_id==asset_id).first()
        if asset_tag: db.session.delete(asset_tag)
    elif asset_type=="gateway":
        if not GatewayRepository.is_from_organization(asset_id, organization_id):
            raise Error.Forbidden("Trying to untag a gateway from other organization")
        asset_tag = db.session.query(GatewayToTag).\
            filter(GatewayToTag.tag_id==tag_id, GatewayToTag.gateway_id==asset_id).first()
        if asset_tag: db.session.delete(asset_tag)
    else:
        raise Error.BadRequest(f"Invalid asset_type: {asset_type}")
    if commit: db.session.commit()

def list_asset_tags(asset_id, asset_type, organization_id):
    if asset_type=="device":
        if not DeviceRepository.is_from_organization(asset_id, organization_id):
            raise Error.Forbidden("Trying to list tags from a device from other organization")
        return db.session.query(Tag).\
            join(DeviceToTag).\
            filter(DeviceToTag.device_id == asset_id).all()
    elif asset_type=="gateway":
        if not GatewayRepository.is_from_organization(asset_id, organization_id):
            raise Error.Forbidden("Trying to list tags from a gateway from other organization")
        return db.session.query(Tag).\
            join(GatewayToTag).\
            filter(GatewayToTag.gateway_id == asset_id).all()
    else:
        raise Error.BadRequest(f"Invalid asset_type: {asset_type}")
