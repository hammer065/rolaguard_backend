from sqlalchemy import Column, BigInteger, Boolean
from sqlalchemy.sql.schema import ForeignKey
from iot_api.user_api import db

class NotificationAlertSettings(db.Model):
    __tablename__ = 'notification_alert_settings'
    user_id = Column(BigInteger, ForeignKey("iot_user.id"), primary_key=True)
    high = Column(Boolean, nullable=False, default=True)
    medium = Column(Boolean, nullable=False, default=True)
    low = Column(Boolean, nullable=False, default=True)
    info = Column(Boolean, nullable=False, default=True)

    def to_dict(self):
        return [
            {
                'name': 'high',
                'enabled': self.high
            },
            {
                'name': 'medium',
                'enabled': self.medium
            },
            {
                'name': 'low',
                'enabled': self.low
            },
            {
                'name': 'info',
                'enabled': self.info
            }
        ]

    def save(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_one(cls, user_id):
        return cls.query.get(user_id)
        
