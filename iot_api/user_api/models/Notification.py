from sqlalchemy import Column, BigInteger, String, ForeignKey, DateTime, desc
from iot_api.user_api import db
from sqlalchemy.orm import relationship
from iot_api import config

class Notification(db.Model):
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    type = Column(String(20), ForeignKey("notification_type.code"), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
    read_at = Column(DateTime(timezone=True), nullable=True)
    alert_id = Column(BigInteger, ForeignKey("alert.id"), nullable=False)
    alert = relationship("Alert", lazy="joined")
    user_id = Column(BigInteger, ForeignKey("iot_user.id"), nullable=False)
    notification_state = Column(String(2000),nullable=True)
    notification_source = Column(String(200),nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'createdAt': "{}".format(self.created_at),
            'readAt': "{}".format(self.read_at) if self.read_at else None,
            'alertId': self.alert_id,
            'alert': self.alert.to_json(),
            'alertType': self.alert.alert_type.to_json(),
            'notificationState': self.notification_state,
            'notificationSource': self.notification_source
        }

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()
    
    @classmethod
    def find(cls, user_id, page = None, size = None):
        query = cls.query.filter(cls.user_id == user_id)

        query = query.order_by(desc(cls.created_at))
        return query.paginate(page=page, per_page=size, error_out=config.ERROR_OUT, max_per_page=config.MAX_PER_PAGE)

    @classmethod
    def find_one(cls, id):
        return cls.query.get(id)

    @classmethod
    def count(cls, user_id, _from = None):
        query = cls.query.filter(cls.user_id == user_id, cls.read_at == None)
        if _from:
            query = query.filter(cls.created_at >= _from )
        return query.count()

    @classmethod
    def commit(cls):
        db.session.commit()

