import iot_logging
log = iot_logging.getLogger(__name__)

from sqlalchemy import func, or_, distinct
from sqlalchemy.sql import select, expression, text

from iot_api.user_api import db
from iot_api.user_api.model import Device


def is_from_organization(device_id, organization_id):
    """ Return a boolean indicatinf if the device belongs to this organization. """
    return db.session.query(Device.query.filter(
        Device.id == device_id,
        Device.organization_id == organization_id
    ).exists()).scalar()