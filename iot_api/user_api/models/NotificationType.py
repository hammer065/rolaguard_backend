from sqlalchemy import Column, BigInteger, String
from iot_api.user_api import db

class NotificationType(db.Model):
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    code = Column(String(20), nullable=False, unique=True)
