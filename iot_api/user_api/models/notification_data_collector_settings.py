from sqlalchemy import Column, BigInteger, Boolean, DateTime, String
from sqlalchemy.orm import relationship
from sqlalchemy.sql.schema import ForeignKey
from iot_api.user_api import db
from iot_api.user_api.model import DataCollector,DataCollectorStatus

class NotificationDataCollectorSettings(db.Model):
    enabled = Column(Boolean, nullable=False, default=True)
    user_id = Column(BigInteger, ForeignKey("iot_user.id"), primary_key=True)
    data_collector_id = Column(BigInteger, ForeignKey("data_collector.id"), primary_key=True)
    data_collector = relationship("DataCollector", lazy="joined")

    def to_dict(self):
        return {
            'enabled': self.enabled,
            'dataCollector': self.data_collector.to_json_for_list(),
            'dataCollectorId': self.data_collector_id
        }

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.remove(self)
        db.session.commit()

    @classmethod
    def find(cls, user_id):
        return cls.query.join(DataCollector).filter(cls.user_id == user_id,DataCollector.deleted_at == None,DataCollector.status!=DataCollectorStatus.DISABLED).all()

    @classmethod
    def find_one(cls, user_id, data_collector_id):
        return cls.query.get((user_id, data_collector_id))

    @classmethod
    def delete_by_criteria(cls, data_collector_id, user_id):
        query = cls.query
        if data_collector_id:
            query = query.filter(cls.data_collector_id == data_collector_id)
        if user_id:
            query.filter(cls.user_id == user_id)
        query.delete()
