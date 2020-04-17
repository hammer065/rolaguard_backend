from sqlalchemy import Column, String, BigInteger, ForeignKey, DateTime, Enum as SQLEnum, desc
from sqlalchemy.orm import relationship

from enum import Enum
from datetime import datetime

from iot_api.user_api import db
from iot_api import cipher_suite, config

import json

class DataCollectorLogEventType(Enum):
    CONNECTED = 'CONNECTED'
    DISCONNECTED = 'DISCONNECTED'
    DISABLED = 'DISABLED'
    CREATED = 'CREATED'
    UPDATED = 'UPDATED'
    ENABLED = 'ENABLED'
    RESTARTED = 'RESTARTED'
    FAILED_PARSING = 'FAILED_PARSING'
    FAILED_LOGIN = 'FAILED_LOGIN'
    DELETED = 'DELETED'


class DataCollectorLogEvent(db.Model):
    __tablename__ = "data_collector_log_event"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    data_collector_id = Column(BigInteger, ForeignKey("data_collector.id"), nullable=False)
    type = Column(SQLEnum(DataCollectorLogEventType))
    created_at = Column(DateTime(timezone=True), nullable=False)
    parameters = Column(String(4096), nullable=False)
    user_id = Column(BigInteger, ForeignKey("iot_user.id"), nullable=True)
    user = relationship("User", lazy="joined")

    def to_dict(self):
        parsed_user = self.user.to_short_info_json() if self.user else None
        return {
            'id': self.id,
            'createdAt': "{}".format(self.created_at),
            'parameters': json.loads(self.parameters),
            'dataCollectorId': self.data_collector_id,
            'type': self.type.name,
            'user': parsed_user,
            'userId': self.user_id
        }
    
    def delete(self):
        db.session.delete(self)
        db.session.commit()
    
    def save(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find(cls, data_collector_id, page = None, size = None):
        query = cls.query.filter(cls.data_collector_id == data_collector_id)
        query = query.order_by(desc(cls.created_at))
        return query.paginate(page=page, per_page=size, error_out=config.ERROR_OUT, max_per_page=config.MAX_PER_PAGE)