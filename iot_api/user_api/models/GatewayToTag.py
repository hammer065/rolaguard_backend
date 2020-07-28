from sqlalchemy import Integer, String, Column, BigInteger, Boolean, ForeignKey
from iot_api.user_api import db

class GatewayToTag(db.Model):
    __tablename__ = 'gateway_tag'
    gateway_id = Column(BigInteger, ForeignKey("gateway.id"), nullable=False, primary_key=True)
    tag_id = Column(BigInteger, ForeignKey("tag.id"), nullable=False, primary_key=True)