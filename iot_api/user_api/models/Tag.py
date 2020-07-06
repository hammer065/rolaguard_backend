from sqlalchemy import Integer, String, Column, BigInteger, Boolean, ForeignKey
from iot_api.user_api import db

class Tag(db.Model):
    __tablename__ = 'tag'
    id = Column(Integer, primary_key=True, autoincrement=True)
    organization_id = Column(BigInteger, ForeignKey("organization.id"), nullable=False)
    name = Column(String(), nullable=False)
    color = Column(String(8), nullable=False)
 