from sqlalchemy import Column, String, BigInteger, ForeignKey

import iot_logging
from iot_api.user_api import db

LOG = iot_logging.getLogger(__name__)


class AppKey(db.Model):
    __tablename__ = 'app_key'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    key = Column(String(32), nullable=False)
    organization_id = Column(BigInteger, ForeignKey("organization.id"), nullable=True)

