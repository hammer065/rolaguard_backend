from sqlalchemy import Table, Column, ForeignKey, func, desc, cast, DateTime, Integer, BigInteger

import iot_logging
from iot_api.user_api import db

LOG = iot_logging.getLogger(__name__)

class StatsCounters(db.Model):
    __tablename__ = 'stats_counters'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    hour = Column(DateTime(timezone=True), nullable=False)
    packets_count = Column(BigInteger, nullable=False, default=0)
    joins_count = Column(BigInteger, nullable=False, default=0)
    alerts_count = Column(BigInteger, nullable=True)
    devices_count = Column(BigInteger, nullable=True)
    organization_id = Column(BigInteger, ForeignKey("organization.id"), nullable=False)
    data_collector_id = Column(BigInteger, ForeignKey("data_collector.id"))

    @classmethod
    def find(cls, organization_id, since, until, data_collectors):
        query = cls.group_by_hour(organization_id, since, until, data_collectors)
        return query.all()

    @classmethod
    def group_by_hour(cls, organization_id, since, until, data_collectors):
        query = cls.query.filter(cls.organization_id == organization_id)
        if since:
            query = query.filter(cls.hour >= since)
        if until:
            query = query.filter(cls.hour <= until)
        if data_collectors and len(data_collectors) > 0:
            query = query.filter(cls.data_collector_id.in_(data_collectors))
        query = query.with_entities(cast(func.sum(cls.alerts_count), Integer).label('alerts_count'),
                                    cast(func.sum(cls.packets_count), Integer).label('packets_count'),
                                    cast(func.sum(cls.devices_count), Integer).label('devices_count'),
                                    cast(func.sum(cls.joins_count), Integer).label('joins_count'),
                                    cls.hour)
        query = query.group_by(cls.hour)
        query = query.order_by(desc(cls.hour))
        return query

    @classmethod
    def group_by_date(cls, organization_id, since, until, data_collectors):
        query = db.session.query(func.date(cls.hour).label('date'),
                                 cast(func.sum(cls.alerts_count), Integer).label('alerts_count'),
                                 cast(func.sum(cls.packets_count), Integer).label('packets_count'),
                                 cast(func.sum(cls.joins_count), Integer).label('joins_count'))\
            .filter(cls.organization_id == organization_id)

        if since:
            query = query.filter(cls.hour >= since)
        if until:
            query = query.filter(cls.hour <= until)
        if data_collectors and len(data_collectors) > 0:
            query = query.filter(cls.data_collector_id.in_(data_collectors))
        query = query.group_by(func.date(cls.hour)).order_by(desc(func.date(cls.hour)))
        return query.all()

    @classmethod
    def max_devices_by_date(cls, organization_id, since, until, data_collectors):
        sum_query = cls.group_by_hour(organization_id, since, until, data_collectors).subquery()
        max_query = db.session.query(func.date(sum_query.c.hour).label('date'), func.max(sum_query.c.devices_count).label('max_devices')).group_by(func.date(sum_query.c.hour)).subquery('max_query')
        query = db.session.query(max_query.c.date, max_query.c.max_devices).order_by(max_query.c.date)
        return query.all()

    def to_json_for_packet(self):
        return {
            'hour': self.hour,
            'count': self.packets_count
        }

    def to_json_for_join(self):
        return {
            'hour': self.hour,
            'count': self.joins_count
        }

    def to_json_for_device(self):
        return {
            'hour': self.hour,
            'count': self.devices_count
        }