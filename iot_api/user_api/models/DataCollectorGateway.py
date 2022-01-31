from sqlalchemy import Column, String, BigInteger, ForeignKey
from iot_api.user_api import db

class DataCollectorGateway(db.Model):
    __tablename__ = 'data_collector_gateway'
    gateway_id = Column(String(120), primary_key=True, nullable=False)
    data_collector_id = Column(BigInteger, ForeignKey('data_collector.id'), primary_key=True, nullable=False)
    gateway_name = Column(String(36), nullable=False)