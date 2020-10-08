from sqlalchemy import Column, String, BigInteger, Integer, DateTime, ForeignKey, Enum as SQLEnum
from iot_api.user_api.models import CounterType

import iot_logging
from iot_api.user_api import db

LOG = iot_logging.getLogger(__name__)

class DeviceCounters(db.Model):
    __tablename__ = 'device_counters'
    device_id = Column(BigInteger, ForeignKey("device.id"), nullable=False, primary_key=True)
    counter_type = Column(SQLEnum(CounterType), nullable=False, primary_key=True)
    hour_of_day = Column(Integer, nullable=False, primary_key=True)
    value = Column(BigInteger, nullable=False, default=0)
    last_update = Column(DateTime(timezone=True), nullable=False)