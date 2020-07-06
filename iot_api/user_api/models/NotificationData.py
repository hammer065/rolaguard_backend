from sqlalchemy import Column, BigInteger, String, ForeignKey, DateTime, desc
from iot_api.user_api import db
from sqlalchemy.orm import relationship
from iot_api import config

class NotificationData(db.Model):
    __tablename__ = 'notification_data'
    user_id = Column(BigInteger, ForeignKey("iot_user.id"), primary_key=True)
    last_read = Column(DateTime(timezone=True), nullable=True)
    ws_sid = Column(String(50), nullable=True)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    @classmethod
    def find_one(cls, user_id):
        return cls.query.get(user_id)

    @classmethod
    def find_one_by_sid(cls, sid):
        return cls.query.filter(cls.ws_sid==sid).first()
