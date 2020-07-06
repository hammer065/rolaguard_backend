from sqlalchemy import Column, BigInteger, Boolean
from sqlalchemy.sql.schema import ForeignKey
from iot_api.user_api import db

class NotificationPreferences(db.Model):
    __tablename__ = 'notification_preferences'
    user_id = Column(BigInteger, ForeignKey("iot_user.id"), primary_key=True)
    sms = Column(Boolean, nullable=False, default=False)
    push = Column(Boolean, nullable=False, default=False)
    email = Column(Boolean, nullable=False, default=False)

    def to_dict(self, phones, emails):
        return [
            {
                'destination': 'sms',
                'enabled': self.sms,
                'additional': phones
            },
            {
                'destination': 'email',
                'enabled': self.email,
                'additional': emails
            },
            {
                'destination': 'push',
                'enabled': self.push
            }
        ]

    def save(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_one(cls, user_id):
        return cls.query.get(user_id)

    @classmethod
    def commit(cls):
        db.session.commit()

    @classmethod
    def rollback(cls):
        db.session.rollback()
        
