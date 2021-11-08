from sqlalchemy import Column, String, BigInteger, ForeignKey, DateTime, Boolean, func, Enum as SQLEnum, desc, Text
from sqlalchemy.orm import relationship

from enum import Enum
from datetime import datetime

import iot_logging
from iot_api.user_api import db
from iot_api import cipher_suite, config


LOG = iot_logging.getLogger(__name__)


class DataCollectorStatus(Enum):
    CONNECTED = 'CONNECTED'
    DISCONNECTED = 'DISCONNECTED'
    DISABLED = 'DISABLED'


class DataCollector(db.Model):
    __tablename__ = "data_collector"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    data_collector_type_id = Column(BigInteger, ForeignKey("data_collector_type.id"), nullable=False)
    type = relationship("DataCollectorType", lazy="joined")
    region = relationship("TTNRegion", lazy="joined")
    policy = relationship("Policy", lazy="joined")
    name = Column(String(120), nullable=False)
    description = Column(String(1000), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
    ip = Column(String(120), nullable=True)
    port = Column(String(120), nullable=True)
    user = Column(String(120), nullable=False)
    password = Column(String(400), nullable=False)
    ssl = Column(Boolean, nullable=True)
    ca_cert  =Column(Text, nullable=True)
    client_cert = Column(Text, nullable=True)
    client_key = Column(Text, nullable=True)
    gateway_id = Column(String(50), nullable=True)
    gateway_name = Column(String(36), nullable=True)
    gateway_api_key = Column(String(120), nullable=True)
    region_id = Column(BigInteger, ForeignKey("ttn_region.id"), nullable=True)
    organization_id = Column(BigInteger, ForeignKey("organization.id"), nullable=False)
    policy_id = Column(BigInteger, ForeignKey("policy.id"), nullable=False)
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    topics = relationship("MqttTopic", lazy="joined")
    status = Column(SQLEnum(DataCollectorStatus))
    verified = Column(Boolean, nullable=False, default=False)

    def to_json(self):
        topics = list(map(lambda topic: topic.to_json(), self.topics))

        password = None
        try:
            password = cipher_suite.decrypt(bytes(self.password, 'utf8')).decode('utf-8')
        except Exception:
            password = ''

        gateway_api_key = None
        try:
            gateway_api_key = cipher_suite.decrypt(bytes(self.gateway_api_key, 'utf8')).decode('utf-8')
        except Exception:
            gateway_api_key = ''

        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'created_at': "{}".format(self.created_at),
            'ip': self.ip,
            'port': self.port,
            'user': self.user,
            'password': password,
            'ssl': self.ssl,
            'ca_cert': self.ca_cert,
            'client_cert': self.client_cert,
            'client_key': self.client_key,
            'organization_id': self.organization_id,
            'policy_id': self.policy_id,
            'gateway_id': self.gateway_id,
            'gateway_name': self.gateway_name,
            'gateway_api_key': gateway_api_key,
            'region_id': self.region_id,
            'policy_name': self.policy.name if self.policy else None,
            'data_collector_type_id': self.data_collector_type_id,
            'type': self.type.to_json(),
            'topics': topics,
            'status': self.status.name,
            'verified': self.verified
        }

    def to_json_for_system(self):
        topics = list(map(lambda topic: topic.to_json(), self.topics))
        password = None
        try:
            password = cipher_suite.decrypt(bytes(self.password, 'utf8')).decode('utf-8')
        except Exception:
            password = ''

        gateway_api_key = None
        try:
            gateway_api_key = cipher_suite.decrypt(bytes(self.gateway_api_key, 'utf8')).decode('utf-8')
        except Exception:
            gateway_api_key = ''

        return {
            'id': self.id,
            'name': self.name,
            'ip': self.ip,
            'port': self.port,
            'user': self.user,
            'password': password,
            'ssl': self.ssl,
            'ca_cert': self.ca_cert,
            'client_cert': self.client_cert,
            'client_key': self.client_key,
            'gateway_id': self.gateway_id,
            'gateway_name': self.gateway_name,
            'gateway_api_key': gateway_api_key,
            'region_id': self.region_id,
            'organization_id': self.organization_id,
            'data_collector_type_id': self.data_collector_type_id,
            'type': self.type.to_json(),
            'topics': topics,
            'status': self.status.name,
            'verified': self.verified
        }

    def to_json_for_list(self):
        gateway_api_key = None
        try:
            gateway_api_key = cipher_suite.decrypt(bytes(self.gateway_api_key, 'utf8')).decode('utf-8')
        except Exception:
            gateway_api_key = ''

        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'created_at': "{}".format(self.created_at),
            'data_collector_type_id': self.data_collector_type_id,
            'gateway_id': self.gateway_id,
            'gateway_name': self.gateway_name,
            'gateway_api_key': gateway_api_key,
            'region_id': self.region_id,
            'type': self.type.to_json(),
            'status': self.status.name,
            'verified': self.verified
        }

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def update_to_db(self):
        db.session.commit()

    def delete_from_db(self):
        self.deleted_at = datetime.now()
        db.session.commit()

    def rollback(self):
        db.session.rollback()

    @classmethod
    def get(cls, id):
        return db.session.query(cls).get(id)

    @classmethod
    def find_with(cls, collector_ids, organization_id):
        try:
            query = cls.query.filter(cls.deleted_at == None)

            if collector_ids is not None:
                query = query.filter(cls.id.in_(collector_ids))

            if organization_id:
                query = query.filter(cls.organization_id == organization_id)

            return query.all()

        except Exception as e:
            LOG.error(e)



    @classmethod
    def find_by_id(cls, id):
        try:
            return cls.query.filter(cls.deleted_at == None).filter(cls.id == id).first()
        except Exception as e:
            LOG.error(e)


    @classmethod
    def find_by_ids(cls, collector_ids):
        try:
            collectors = []

            for collector_id in collector_ids:
                collectors.append(DataCollector.find_by_id(collector_id))

            return collectors
        except Exception as e:
            LOG.error(e)

    @classmethod
    def count(cls, organization_id, policy_id=None):
        try:
            query = db.session.query(cls.id).filter(cls.deleted_at == None)\
                .filter(cls.organization_id == organization_id)

            if policy_id:
                query = query.filter(cls.policy_id == policy_id)

            return query.count()
        except Exception as e:
            LOG.error(e)

    @classmethod
    def count_exclude_disabled(cls, user):
        # It's here to avoid circular import conflict
        from iot_api.user_api.model import get_user_collector_ids
        try:
            query = db.session.query(cls.id).filter(cls.deleted_at == None)\
                .filter(cls.organization_id == user.organization_id)\
                .filter(cls.status != DataCollectorStatus.DISABLED)

            user_collector_ids = get_user_collector_ids(user)

            if user_collector_ids and len(user_collector_ids) > 0:
                query = query.filter(DataCollector.id.in_(user_collector_ids))

            return query.count()
        except Exception as e:
            LOG.error(e)

    @classmethod
    def find_by_user(cls, user, page=None, size=None):
        # It's here to avoid circular import conflict
        from iot_api.user_api.model import get_user_collector_ids, is_system_user
        try:
            query = cls.query.filter(cls.deleted_at == None)

            # I don't know if this method is ever called by the system user. But if it happens it should see everything.

            if not is_system_user(user.id):
                query = query.filter(cls.organization_id == user.organization_id)
                user_collector_ids = get_user_collector_ids(user)

                if user_collector_ids and len(user_collector_ids) > 0:
                    query = query.filter(DataCollector.id.in_(user_collector_ids))

            query = query.order_by(desc(cls.created_at))

            return query.paginate(page=page, per_page=size, error_out=config.ERROR_OUT,
                                  max_per_page=config.MAX_PER_PAGE)
        except Exception as e:
            LOG.error(e)

    @classmethod
    def find_by_organization_id_and_policy_id(cls, organization_id, policy_id):
        try:
            query = cls.query.filter(cls.deleted_at == None)

            if organization_id:
                query = query.filter(cls.organization_id == organization_id)

            if policy_id:
                query = query.filter(cls.policy_id == policy_id)
            query = query.order_by(desc(cls.created_at))

            return query.all()
        except Exception as e:
            LOG.error(e)

    @classmethod
    def find_and_count_all(cls, user, _from, to, types, resolved, risks, data_collectors):
        # It's here to avoid circular import conflict
        from iot_api.user_api.model import Alert, AlertType, get_user_collector_ids, is_system_user
        try:
            query = db.session.query(Alert.data_collector_id.label('id'), func.count(1).label('count')) \
                .join(DataCollector) \
                .filter(Alert.show == True)

            # I don't know if this method is ever called by the system user. But if it happens it should see everything.

            if not is_system_user(user.id):
                query = query.filter(cls.organization_id == user.organization_id)
                user_collector_ids = get_user_collector_ids(user, data_collectors)

                if user_collector_ids and len(user_collector_ids) > 0:
                    query = query.filter(DataCollector.id.in_(user_collector_ids))

            if _from:
                query = query.filter(Alert.created_at >= _from)

            if to:
                query = query.filter(Alert.created_at <= to)

            if types and len(types) > 0:
                query = query.filter(Alert.type.in_(types))

            if resolved is not None:
                if resolved:
                    query = query.filter(Alert.resolved_at != None)
                else:
                    query = query.filter(Alert.resolved_at == None)

            if risks and len(risks) > 0:
                query = query.join(AlertType).filter(AlertType.risk.in_(risks))
            query = query.group_by(Alert.data_collector_id)

            return query.all()
        except Exception as e:
            LOG.error(e)
