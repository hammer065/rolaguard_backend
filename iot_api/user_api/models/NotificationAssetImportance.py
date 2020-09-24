from sqlalchemy import Column, BigInteger, Boolean
from sqlalchemy.sql.schema import ForeignKey
from iot_api.user_api import db

class NotificationAssetImportance(db.Model):
    __tablename__ = 'notification_asset_importance'
    user_id = Column(BigInteger, ForeignKey("iot_user.id"), primary_key=True)
    high = Column(Boolean, nullable=False, default=True)
    medium = Column(Boolean, nullable=False, default=True)
    low = Column(Boolean, nullable=False, default=True)

    def save(self):
        db.session.add(self)
        db.session.commit()
        return self

    @classmethod
    def get_with(cls, user_id):
        return cls.query.get(user_id)