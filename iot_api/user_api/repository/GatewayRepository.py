import iot_logging
log = iot_logging.getLogger(__name__)

from sqlalchemy import func, or_, distinct
from sqlalchemy.sql import select, expression, text

from iot_api.user_api import db
from iot_api.user_api.model import Gateway
from iot_api.user_api.models import GatewayToTag

def is_from_organization(gateway_id, organization_id):
    """ Return a boolean indicating if the gateway belongs to this organization. """
    return db.session.query(Gateway.query.filter(
        Gateway.id == gateway_id,
        Gateway.organization_id == organization_id
    ).exists()).scalar()

def has_all_tags(gateway_id, tag_id_list):
    """ Return a boolean indicating whether the gateway is tagged with every tag in the list or not """
    return db.session.query(GatewayToTag).filter(
        GatewayToTag.gateway_id == gateway_id,
        GatewayToTag.tag_id.in_(tag_id_list)
    ).count() == len(tag_id_list)