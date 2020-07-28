from sqlalchemy import Integer, String, Column, BigInteger, Boolean, ForeignKey
from iot_api.user_api import db

class DeviceToTag(db.Model):
    __tablename__ = 'device_tag'
    device_id = Column(BigInteger, ForeignKey("device.id"), nullable=False, primary_key=True)
    tag_id = Column(BigInteger, ForeignKey("tag.id"), nullable=False, primary_key=True)