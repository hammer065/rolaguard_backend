from iot_api import bcrypt
from iot_api.user_api.enums import RoleTypes
from iot_api.user_api.models.DataCollector import *
from iot_api import config

from sqlalchemy import Table, Column, ForeignKey, func, desc, asc, cast, case, \
    DateTime, String, Integer, BigInteger, SmallInteger, Float, Boolean
from sqlalchemy.orm import relationship

import json
from datetime import datetime


LOG = iot_logging.getLogger(__name__)


class Organization(db.Model):
    __tablename__ = "organization"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    name = db.Column(db.String(120), unique=True)
    country = db.Column(db.String(120))
    region = db.Column(db.String(120))
    users = db.relationship("User", backref="organization", lazy=True)
    
    def to_json(self):
        return {
            "name": self.name,
            "country": self.country,
            "region": self.region
        }

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def update_to_db(self):
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def find_by_name(cls, name):
        return cls.query.filter_by(name=name).first()

    @classmethod
    def find_by_id(cls, organization_id, json):
        if json:
            return {"organizations": list(map(lambda organization: organization.to_json(), cls.query.filter_by(
                id=organization_id).all()))}
        else:
            return cls.query.filter_by(id=organization_id).first()

    @classmethod
    def return_all(cls, json):
        if json:
            return {"organizations": list(map(lambda organization: organization.to_json(), cls.query.all()))}
        else:
            return cls.query.all()


user_to_data_collector_association_table = Table(
    'user_to_data_collector',
    db.Model.metadata,
    Column('user_id', Integer, ForeignKey('iot_user.id')),
    Column('data_collector_id', Integer, ForeignKey('data_collector.id'))
)


class User(db.Model):
    __tablename__ = "iot_user"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    username = db.Column(db.String(32), index=True, unique=True, nullable=False)
    full_name = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(320), unique=True, nullable=False)
    phone = db.Column(db.String(30), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    user_roles = db.relationship("UserToUserRole", back_populates="user")
    organization_id = db.Column(db.BigInteger, db.ForeignKey("organization.id"), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=False)
    deleted = db.Column(db.Boolean, nullable=False, default=False)
    blocked = db.Column(db.Boolean, nullable=False, default=False)
    collectors = relationship("DataCollector", secondary=user_to_data_collector_association_table, lazy="joined")

    def to_json(self):
        try:
            organization_name = Organization.find_by_id(self.organization_id, False).name

            user_roles = list(map(lambda x: x.user_role_id, self.user_roles))  # listing user roles for active user

            if not user_roles:  # listing user roles for not active user created before delay
                account_activation_list = AccountActivation.find_last_tokens_by_user_id(self.id)
                if account_activation_list:
                    account_activation = account_activation_list[0]
                    user_roles = list(account_activation.user_roles_id)
                    user_roles = list(filter(lambda x: x != ',', user_roles))
                    user_roles = [int(x) for x in user_roles]

            return {
                "id": self.id,
                "username": self.username,
                "full_name": self.full_name,
                "phone": self.phone,
                "email": self.email,
                "user_roles": user_roles,
                "organization_id": self.organization_id,
                "active": self.active,
                "organization_name": organization_name
            }
        except Exception as e:
            LOG.error(e)

    def to_short_info_json(self):
        return {
            "id": self.id,
            "username": self.username,
            "full_name": self.full_name,
        }

    @staticmethod
    def generate_hash(password):
        return bcrypt.generate_password_hash(password).decode('utf - 8')

    @staticmethod
    def verify_hash(password, hash):
        return bcrypt.check_password_hash(hash, password)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def update_to_db(self):
        db.session.commit()

    @classmethod
    def find_by_username(cls, username):
        try:
            return cls.query.filter_by(username=username.lower()).first()
        except Exception as e:
            LOG.error(e)

    @classmethod
    def find_by_id(cls, user_id):
        try:
            return cls.query.filter_by(id=user_id).first()
        except Exception as e:
            LOG.error(e)

    @classmethod
    def find_all_user_by_organization_id(cls, organization_id):
        try:
            return cls.query.filter(cls.id == UserToUserRole.user_id)\
                .filter(~cls.user_roles.any(UserToUserRole.user_role_id == 9))\
                .filter_by(organization_id=organization_id).all()
        except Exception as e:
            LOG.error(e)

    @classmethod
    def get_count_by_organization_id(cls, organization_id):
        try:
            return cls.query.filter_by(organization_id=organization_id).count()
        except Exception as e:
            LOG.error(e)

    @classmethod
    def find_by_email(cls, email):
        try:
            return cls.query.filter_by(email=email.lower()).all()
            #filter(cls.id == UserToUserRole.user_id). -> commented due to the delay in creating the table user_to_user_role after user is activated
        except Exception as e:
            LOG.error(e)

    @classmethod
    def find(cls, organization_id=None, page=None, size=None):
        try:
            q1 = cls.query.filter(cls.deleted == False).filter(~cls.user_roles.any(UserToUserRole.user_role_id == 9))\
                .filter(cls.id == UserToUserRole.user_id)
            q2 = cls.query.filter(cls.active == False).filter(cls.id == AccountActivation.user_id)
            if organization_id is not None:
                q1 = q1.filter(cls.organization_id == organization_id)
                q2 = q2.filter(cls.organization_id == organization_id)
            query = q1.union(q2)
            return query.paginate(page=page, per_page=size, error_out=config.ERROR_OUT,
                                  max_per_page=config.MAX_PER_PAGE)
        except Exception as e:
            LOG.error(e)

    @classmethod
    def get_count_all(cls):
        try:
            return cls.query.count()
        except Exception as e:
            LOG.error(e)


class UserRole(db.Model):
    __tablename__ = "user_role"

    id = db.Column(db.BigInteger, primary_key=True)
    role_name = db.Column(db.String(120), unique=True, nullable=False)

    def to_json(self):
        return {
            'id': self.id,
            'role_name': self.role_name
        }

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def update_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_id(cls, id):
        return cls.query.filter_by(id=id).first()

    @classmethod
    def find_by_role_name(cls, role_name):
        return cls.query.filter_by(role_name=role_name).first()

    @classmethod
    def return_all(cls, json):
        roles = cls.query.filter(cls.id != 9).all()
        if json:
            return {"user_roles": list(map(lambda user_role: user_role.to_json(), roles))}
        else:
            return roles


class UserToUserRole(db.Model):
    __tablename__ = "user_to_user_role"

    user_id = db.Column(db.BigInteger, db.ForeignKey(
        "iot_user.id"), primary_key=True)
    user_role_id = db.Column(db.BigInteger, db.ForeignKey(
        "user_role.id"), primary_key=True)
    user = db.relationship("User", back_populates="user_roles")

    def to_json(self):
        return {
            "user_id": self.user_id,
            "user_role_id": self.user_role_id,
        }

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def update_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def find_all_user_by_user_role_id(cls, user_role_id):
        return cls.query.filter_by(user_role_id=user_role_id).all()

    @classmethod
    def find_all_user_role_by_user_id(cls, user_id):
        return cls.query.filter_by(user_id=user_id).all()

    @classmethod
    def find_by_user_id_and_user_role_id(cls, user_id, user_role_id):
        return cls.query.filter_by(user_id=user_id, user_role_id=user_role_id).first()


class AccountActivation(db.Model):
    __tablename__ = "account_activation"

    id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey(
        "iot_user.id"), nullable=False)
    token = db.Column(db.String(500), nullable=False)
    creation_date = db.Column(db.DateTime(timezone=True), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    # organization_id = db.Column(Integer, nullable=True)
    user_roles_id = db.Column(String(40))

    def to_json(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'token': self.token,
            'creation_date': self.creation_date,
            'active': self.active
        }

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def update_to_db(self):
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def find_by_token(cls, token):
        return cls.query.filter_by(token=token, active=True).first()

    @classmethod
    def find_active_tokens_by_user_id(cls, user_id):
        return cls.query.filter_by(user_id=user_id, active=True).all()

    @classmethod
    def find_last_tokens_by_user_id(cls, user_id):
        return cls.query.filter_by(user_id=user_id).order_by(desc(AccountActivation.creation_date))


class AlertType(db.Model):
    __tablename__ = 'alert_type'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    code = Column(String(20), nullable=False, unique=True)
    name = Column(String(120), nullable=False)
    message = Column(String(4096), nullable=True)
    risk = Column(String(20), nullable=False)
    description = Column(String(3000), nullable=False)
    parameters = Column(String(4096), nullable=True)
    technical_description = Column(String(3000), nullable=True)
    recommended_action = Column(String(3000), nullable=True)
    quarantine_timeout = Column(Integer, nullable=True, default=0)

    def to_json(self):
        return {
            'id': self.id,
            'code': self.code,
            'name': self.name,
            'message': self.message,
            'risk': self.risk,
            'description': self.description,
            'technicalDescription': self.technical_description,
            'recommendedAction': self.recommended_action,
            'parameters': json.loads(self.parameters if self.parameters is not None else '{}')
        }

    @classmethod
    def find_all(cls):
        return cls.query.all()

    @classmethod
    def find_and_count_all(cls, organization_id, _from, to, resolved, risks, data_collectors, types):
        try:
            query = db.session.query(Alert.type.label('type'), func.count(1).label('count'))\
                .join(DataCollector)\
                .filter(DataCollector.organization_id == organization_id)\
                .filter(Alert.show == True)

            if _from:
                query = query.filter(Alert.created_at >= _from)
            if to:
                query = query.filter(Alert.created_at <= to)
            if resolved is not None:
                if resolved:
                    query = query.filter(Alert.resolved_at != None)
                else:
                    query = query.filter(Alert.resolved_at == None)
            if risks and len(risks) > 0:
                query = query.join(AlertType).filter(AlertType.risk.in_(risks))
            if data_collectors and len(data_collectors) > 0:
                query = query.filter(Alert.data_collector_id.in_(data_collectors))
            if types and len(types)>0:
                query = query.filter(Alert.type.in_(types))
            query = query.group_by(Alert.type)
            return query.all()
        except Exception as e:
            LOG.error(e)

    @classmethod
    def find_one(cls, code):
        return cls.query.filter(cls.code == code).first()


class Alert(db.Model):
    __tablename__ = 'alert'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    type = Column(String(20), ForeignKey("alert_type.code"), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
    packet_id = Column(BigInteger, ForeignKey("packet.id"), nullable=False)
    device_id = Column(BigInteger, ForeignKey("device.id"), nullable=True)
    device_session_id = Column(BigInteger, ForeignKey("device_session.id"), nullable=True)
    gateway_id = Column(BigInteger, ForeignKey("gateway.id"), nullable=True)
    device_auth_id = Column(BigInteger, ForeignKey("device_auth_data.id"), nullable=True)
    data_collector_id = Column(BigInteger, ForeignKey("data_collector.id"), nullable=False)
    parameters = Column(String(4096), nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by_id = Column(BigInteger, ForeignKey("iot_user.id"), nullable=True)
    resolution_comment = Column(String(1024), nullable=True)
    show = Column(Boolean, nullable=False, default=True)

    resolved_by = relationship("User", lazy="joined")
    alert_type = relationship("AlertType", lazy="joined")
    data_collector = relationship("DataCollector", lazy="joined")
    device = relationship("Device", lazy="joined")
    gateway = relationship("Gateway", lazy="joined")

    def to_json(self):
        parsed_user = self.resolved_by.to_short_info_json() if self.resolved_by else None
        return {
            'id': self.id,
            'type': self.type,
            'created_at': "{}".format(self.created_at) if self.created_at else None,
            'packet_id': self.packet_id,
            'device_id': self.device_id,
            'data_collector_id': self.data_collector_id,
            'data_collector_name': self.data_collector.name,
            'device_session_id': self.device_session_id,
            'gateway_id': self.gateway_id,
            'device_auth_id': self.device_auth_id,
            'parameters': json.loads(self.parameters if self.parameters is not None else '{}'),
            'resolved_at': None if self.resolved_at is None else "{}".format(self.resolved_at),
            'resolution_comment': self.resolution_comment,
            'resolved_by_id': self.resolved_by_id,
            'resolved_by': parsed_user,
            'asset_importance': self.get_asset_importance()
        }

    def to_count_json(self):
        return {
            'id': self.id,
            'type': self.type,
            'created_at': "{}".format(self.created_at)
        }

    def get_asset_importance(self):
        if self.device:
            asset_importance = self.device.importance.value
        elif self.gateway:
            asset_importance = self.gateway.importance.value
        else:
            asset_importance = None
        return asset_importance

    @classmethod
    def find_one(cls, id):
        return cls.query.filter(cls.id == id).first()

    @classmethod
    def find(cls, organization_id, since, until, types, resolved, risks, data_collectors, order_by, page, size):
        try:
            query = db.session.query(Alert)\
                .join(DataCollector)\
                .filter(DataCollector.organization_id == organization_id)\
                .filter(cls.show == True)

            if since:
                query = query.filter(cls.created_at >= since)
            if until:
                query = query.filter(cls.created_at <= until)
            if types and len(types) > 0:
                query = query.filter(cls.type.in_(types))
            if resolved is not None:
                if resolved:
                    query = query.filter(cls.resolved_at != None)
                else:
                    query = query.filter(cls.resolved_at == None)
            if risks and len(risks) > 0:
                query = query.filter(AlertType.code == cls.type).filter(AlertType.risk.in_(risks))
            if data_collectors and len(data_collectors) > 0:
                query = query.filter(cls.data_collector_id.in_(data_collectors))
            if order_by and 'ASC' in order_by:
                query = query.order_by(asc(cls.created_at))
            else:
                query = query.order_by(desc(cls.created_at))

            if page is not None and size:
                query = query.limit(size).offset(page*size)

            result = query.all()
            # print(f"found records: {len(result)}")
            return result
        except Exception as e:
            LOG.error(e)

    @classmethod
    def find_by_gateway_id(cls, gateway_id, organization_id, since, until, types, resolved, risks, order_by, page, size):
        query = db.session.query(Alert)\
                .join(DataCollector)\
                .filter(DataCollector.organization_id == organization_id)\
                .filter(cls.show == True)\
                .filter(cls.gateway_id == gateway_id)

        if since:
            query = query.filter(cls.created_at >= since)
        if until:
            query = query.filter(cls.created_at <= until)
        if types and len(types) > 0:
            query = query.filter(cls.type.in_(types))
        if resolved is not None:
            if resolved:
                query = query.filter(cls.resolved_at != None)
            else:
                query = query.filter(cls.resolved_at == None)
        if risks and len(risks) > 0:
            query = query.filter(AlertType.code == cls.type).filter(AlertType.risk.in_(risks))
        if order_by:
            order_field = order_by[0]
            order_direction = order_by[1]
            if 'ASC' == order_direction:
                query = query.order_by(asc(getattr(cls, order_field)))
            else:
                query = query.order_by(desc(getattr(cls, order_field)))
        else:
            query = query.order_by(desc(cls.created_at)) # newest first if no order_by parameter is specified
        if page and size:
            return query.paginate(page=page, per_page=size, error_out=config.ERROR_OUT, max_per_page=config.MAX_PER_PAGE)
      
        return query.all()

    @classmethod
    def find_by_device_id(cls, device_id, organization_id, since, until, types, resolved, risks, order_by, page, size):
        query = db.session.query(Alert)\
                .join(DataCollector)\
                .filter(DataCollector.organization_id == organization_id)\
                .filter(cls.show == True)\
                .filter(cls.device_id == device_id)

        if since:
            query = query.filter(cls.created_at >= since)
        if until:
            query = query.filter(cls.created_at <= until)
        if types and len(types) > 0:
            query = query.filter(cls.type.in_(types))
        if resolved is not None:
            if resolved:
                query = query.filter(cls.resolved_at != None)
            else:
                query = query.filter(cls.resolved_at == None)
        if risks and len(risks) > 0:
            query = query.filter(AlertType.code == cls.type).filter(AlertType.risk.in_(risks))
        if order_by:
            order_field = order_by[0]
            order_direction = order_by[1]
            if 'ASC' == order_direction:
                query = query.order_by(asc(getattr(cls, order_field)))
            else:
                query = query.order_by(desc(getattr(cls, order_field)))
        else:
            query = query.order_by(desc(cls.created_at)) # newest first if no order_by parameter is specified
        if page and size:
            return query.paginate(page=page, per_page=size, error_out=config.ERROR_OUT, max_per_page=config.MAX_PER_PAGE)
        
        return query.all()

    @classmethod
    def count(cls, organization_id, since, until, types, resolved, risks, data_collectors):
        try:
            query = db.session.query(func.count(1).label('count'))\
                .filter(cls.data_collector_id == DataCollector.id)\
                .filter(DataCollector.organization_id == organization_id) \
                .filter(cls.show == True)

            if since:
                query = query.filter(cls.created_at >= since)
            if until:
                query = query.filter(cls.created_at <= until)
            if types and len(types) > 0:
                query = query.filter(cls.type.in_(types))
            if resolved is not None:
                if resolved:
                    query = query.filter(cls.resolved_at != None)
                else:
                    query = query.filter(cls.resolved_at == None)
            if risks and len(risks) > 0:
                query = query.filter(cls.type == AlertType.code).filter(AlertType.risk.in_(risks))
            if data_collectors and len(data_collectors) > 0:
                query = query.filter(cls.data_collector_id.in_(data_collectors))

            return query.scalar()
        except Exception as e:
            LOG.error(e)

    @classmethod
    def count_by_date(cls, organization_id, since, until, types, resolved, risks):
        try:
            query = db.session.query(func.date(cls.created_at).label('date'), func.count(1).label('count'))\
                .filter(cls.data_collector_id == DataCollector.id)\
                .filter(DataCollector.organization_id == organization_id) \
                .filter(cls.show == True)

            if risks and len(risks) > 0:
                query = query.join(AlertType).filter(AlertType.risk.in_(risks))
            if since:
                query = query.filter(cls.created_at >= since)
            if until:
                query = query.filter(cls.created_at <= until)
            if types and len(types) > 0:
                query = query.filter(cls.type.in_(types))
            if resolved is not None:
                if resolved:
                    query = query.filter(cls.resolved_at != None)
                else:
                    query = query.filter(cls.resolved_at == None)
            query = query.group_by(func.date(cls.created_at)).order_by(asc(func.date(cls.created_at)))
            return query.all()
        except Exception as e:
            LOG.error(e)

    @classmethod
    def count_by_hour(cls, organization_id, since, until, types, resolved, risks):
        try:
            query = db.session\
                .query(func.date_trunc('hour', cls.created_at).label('hour'), func.count(1).label('count'))\
                .filter(cls.data_collector_id == DataCollector.id)\
                .filter(DataCollector.organization_id == organization_id) \
                .filter(cls.show == True)

            if since:
                query = query.filter(cls.created_at >= since)
            if until:
                query = query.filter(cls.created_at <= until)
            if types and len(types) > 0:
                query = query.filter(cls.type.in_(types))
            if resolved is not None:
                if resolved:
                    query = query.filter(cls.resolved_at != None)
                else:
                    query = query.filter(cls.resolved_at == None)
            if risks and len(risks) > 0:
                query = query.join(AlertType).filter(AlertType.risk.in_(risks))
            query = query\
                .group_by(func.date_trunc('hour', cls.created_at))\
                .order_by(asc(func.date_trunc('hour', cls.created_at)))
            return query.all()
        except Exception as e:
            LOG.error(e)

    def update(self):
        db.session.commit()
    
    @classmethod
    def group_by_date_and_risk(cls, organization_id, since, until, types, resolved, data_collectors):
        try:
            query = db.session.query(func.date(cls.created_at).label('date'), AlertType.risk.label('risk'))\
                .filter(cls.data_collector_id == DataCollector.id)\
                .filter(DataCollector.organization_id == organization_id) \
                .filter(cls.show == True)

            query = query.join(AlertType)
            if since:
                query = query.filter(cls.created_at >= since)
            if until:
                query = query.filter(cls.created_at <= until)
            if types and len(types) > 0:
                query = query.filter(cls.type.in_(types))
            if resolved is not None:
                if resolved:
                    query = query.filter(cls.resolved_at != None)
                else:
                    query = query.filter(cls.resolved_at == None)
            if data_collectors and len(data_collectors) > 0:
                query = query.filter(cls.data_collector_id.in_(data_collectors))
            return query.distinct().all()
        except Exception as e:
            LOG.error(e)

    @classmethod
    def group_by_hour_and_risk(cls, organization_id, since, until, types, resolved, data_collectors):
        try:
            query = db.session\
                .query(func.date_trunc('hour', cls.created_at).label('hour'), AlertType.risk.label('risk'))\
                .filter(cls.data_collector_id == DataCollector.id)\
                .filter(DataCollector.organization_id == organization_id) \
                .filter(cls.show == True)

            query = query.join(AlertType)
            if since:
                query = query.filter(cls.created_at >= since)
            if until:
                query = query.filter(cls.created_at <= until)
            if types and len(types) > 0:
                query = query.filter(cls.type.in_(types))
            if resolved is not None:
                if resolved:
                    query = query.filter(cls.resolved_at != None)
                else:
                    query = query.filter(cls.resolved_at == None)
            if data_collectors and len(data_collectors) > 0:
                query = query.filter(cls.data_collector_id.in_(data_collectors))
            return query.distinct().all()
        except Exception as e:
            LOG.error(e)


class AssetImportance(Enum):
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'

class Gateway(db.Model):
    __tablename__ = 'gateway'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    gw_hex_id = Column(String(100), nullable=True)
    name = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    location_latitude = Column(Float, nullable=True)
    location_longitude = Column(Float, nullable=True)
    data_collector_id = Column(BigInteger, db.ForeignKey("data_collector.id"), nullable=False)
    organization_id = Column(BigInteger, db.ForeignKey("organization.id"), nullable=False)
    connected = Column(Boolean, nullable=False, default=True)
    last_activity = Column(DateTime(timezone=True), nullable=False)
    activity_freq = Column(Float, nullable=True)
    npackets_up = Column(BigInteger, nullable=False, default=0)
    npackets_down = Column(BigInteger, nullable=False, default=0)
    importance = Column(SQLEnum(AssetImportance))

    def to_json(self):
         return {
            'id': self.id,
            'gw_hex_id': self.gw_hex_id,
            'name': self.name,
            'vendor': self.vendor,
            'location': {
                'latitude': self.location_latitude,
                'longitude': self.location_longitude
            },
            'data_collector_id': self.data_collector_id,
            'organization_id': self.organization_id,
            'connected': self.connected,
            'last_activity': "{}".format(self.last_activity),
            'activity_freq': self.activity_freq,
            'importance': self.importance.value,
            'npackets_up': self.npackets_up,
            'npackets_down': self.npackets_down
        }
    

class Device(db.Model):
    __tablename__ = 'device'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    dev_eui = Column(String(16), nullable=False)
    name = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    app_name = Column(String, nullable=True)
    join_eui = Column(String(16), nullable=True)
    organization_id = Column(BigInteger, ForeignKey("organization.id"), nullable=False)
    data_collector_id = Column(BigInteger, db.ForeignKey("data_collector.id"), nullable=False)
    importance = Column(SQLEnum(AssetImportance))

    repeated_dev_nonce = Column(Boolean, nullable=True)
    join_request_counter = Column(Integer, nullable=False, default=0)
    join_accept_counter = Column(Integer, nullable=False, default=0)
    has_joined = Column(Boolean, nullable=True, default=False)
    join_inferred = Column(Boolean, nullable=True, default=False)
    is_otaa = Column(Boolean, nullable=True)
    last_packet_id = Column(BigInteger, ForeignKey("packet.id"), nullable=True)
    first_up_timestamp = Column(db.DateTime(timezone=True), nullable=True)
    last_up_timestamp = Column(DateTime(timezone=True), nullable=True)

    pending_first_connection = Column(Boolean, nullable=False, default=True)
    connected = Column(Boolean, nullable=False, default=True)
    last_activity = Column(DateTime(timezone=True), nullable=True)
    activity_freq = Column(Float, nullable=True)
    npackets_up = Column(BigInteger, nullable=False, default=0)
    npackets_down = Column(BigInteger, nullable=False, default=0)
    npackets_lost = Column(Float, nullable=False, default=0)
    max_rssi = Column(Float, nullable=True)
    max_lsnr = Column(Float, nullable=True)
    ngateways_connected_to = Column(BigInteger, nullable=False, default=0)
    payload_size = Column(BigInteger, nullable=True)

    last_packets_list = Column(String(2048), nullable=True, default='[]')

    def to_json(self):
        return {
            'id': self.id,
            'dev_eui': self.dev_eui,
            'name': self.name,
            'vendor': self.vendor,
            'app_name': self.app_name,
            'join_eui': self.join_eui,
            'data_collector_id': self.data_collector_id,
            'organization_id': self.organization_id,
            'first_up_timestamp': "{}".format(self.first_up_timestamp),
            'last_up_timestamp': "{}".format(self.last_up_timestamp),
            'repeated_dev_nonce': self.repeated_dev_nonce,
            'join_request_counter': self.join_request_counter,
            'join_accept_counter': self.join_request_counter,
            'has_joined': self.has_joined,
            'join_inferred': self.join_inferred,
            'is_otaa': self.is_otaa,
            'last_packet_id': self.last_packet_id,
            'connected': self.connected,
            'last_activity': "{}".format(self.last_activity),
            'activity_freq': self.activity_freq,
            'importance': self.importance.value,
            'npackets_up': self.npackets_up,
            'npackets_down': self.npackets_down,
            'npackets_lost': self.npackets_lost,
            'max_rssi': self.max_rssi,
            'pending_first_connection': self.pending_first_connection
        }

    @classmethod
    def find(cls, organization_id, since, until, page, size):
        query = cls.query.filter(cls.organization_id == organization_id)
        if since:
            query = query.filter(cls.last_up_timestamp >= since)
        if until:
            query = query.filter(cls.last_up_timestamp <= until)
        query = query.order_by(desc(cls.last_up_timestamp))
        if page is not None and size:
            query = query.limit(size).offset(page*size)
        return query.all()

    @classmethod
    def count_by_date(cls, organization_id, since, until):
        query = db.session.query(func.date(cls.last_up_timestamp).label('date'), func.count(1).label('count'))\
            .filter(cls.organization_id == organization_id)
        if since:
            query = query.filter(cls.last_up_timestamp >= since)
        if until:
            query = query.filter(cls.last_up_timestamp <= until)
        query = query.group_by(func.date(cls.last_up_timestamp))
        return query.all()

    @classmethod
    def count_by_hour(cls, organization_id, since, until):
        query = db.session\
            .query(func.date_trunc('hour', cls.last_up_timestamp).label('hour'), func.count(1).label('count'))\
            .filter(cls.organization_id == organization_id)
        if since:
            query = query.filter(cls.last_up_timestamp >= since)
        if until:
            query = query.filter(cls.last_up_timestamp <= until)
        query = query.group_by(func.date_trunc('hour', cls.last_up_timestamp))
        return query.all()
    

class GatewayToDevice(db.Model):
    __tablename__ = 'gateway_to_device'
    gateway_id = Column(BigInteger, db.ForeignKey("gateway.id"), nullable=False, primary_key=True)
    device_id = Column(BigInteger, db.ForeignKey("device.id"), nullable=False, primary_key=True)


class DeviceSession(db.Model):
    __tablename__ = 'device_session'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    may_be_abp = Column(Boolean, nullable=True)
    reset_counter = Column(Integer, nullable=False, default=0)
    is_confirmed = Column(Boolean, nullable=True)
    dev_addr = Column(String(8), nullable=False)
    up_link_counter = Column(Integer, nullable=False, default=-1)
    down_link_counter = Column(Integer, nullable=False, default=-1)
    max_down_counter = Column(Integer, nullable=False, default=-1)
    max_up_counter = Column(Integer, nullable=False, default=-1)
    total_down_link_packets = Column(BigInteger, nullable=False, default=0)
    total_up_link_packets = Column(BigInteger, nullable=False, default=0)
    first_down_timestamp = Column(DateTime(timezone=True), nullable=True)
    first_up_timestamp = Column(DateTime(timezone=True), nullable=True)
    last_down_timestamp = Column(DateTime(timezone=True), nullable=True)
    last_up_timestamp = Column(DateTime(timezone=True), nullable=True)
    device_id = Column(BigInteger, ForeignKey("device.id"), nullable=True)
    organization_id = Column(BigInteger, ForeignKey("organization.id"), nullable=False)
    data_collector_id = Column(BigInteger, db.ForeignKey("data_collector.id"), nullable=False)
    device_auth_data_id = Column(BigInteger, ForeignKey("device_auth_data.id"), nullable=True)
    last_packet_id = Column(BigInteger, ForeignKey("packet.id"), nullable=True)


class Packet(db.Model):
    __tablename__ = 'packet'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    date = Column(DateTime(timezone=True), nullable=False)
    topic = Column(String(256), nullable=True)
    data_collector_id = Column(BigInteger, ForeignKey("data_collector.id"), nullable=False)
    organization_id = Column(BigInteger, ForeignKey("organization.id"), nullable=False)
    gateway = Column(String(16), nullable=True)
    tmst = Column(BigInteger, nullable=True)
    chan = Column(SmallInteger, nullable=True)
    rfch = Column(Integer, nullable=True)
    seqn = Column(Integer, nullable=True)
    opts = Column(String(20), nullable=True)
    port = Column(Integer, nullable=True)
    freq = Column(Float, nullable=True)
    stat = Column(SmallInteger, nullable=True)
    modu = Column(String(4), nullable=True)
    datr = Column(String(50), nullable=True)
    codr = Column(String(10), nullable=True)
    lsnr = Column(Float, nullable=True)
    rssi = Column(Integer, nullable=True)
    size = Column(Integer, nullable=True)
    data = Column(String(300), nullable=True)
    m_type = Column(String(20), nullable=True)
    major = Column(String(10), nullable=True)
    mic = Column(String(8), nullable=True)
    join_eui = Column(String(16), nullable=True)
    dev_eui = Column(String(16), nullable=True)
    dev_nonce = Column(Integer, nullable=True)
    dev_addr = Column(String(8), nullable=True)
    adr = Column(Boolean, nullable=True)
    ack = Column(Boolean, nullable=True)
    adr_ack_req = Column(Boolean, nullable=True)
    f_pending = Column(Boolean, nullable=True)
    class_b = Column(Boolean, nullable=True)
    f_count = Column(Integer, nullable=True)
    f_opts = Column(String(500), nullable=True)
    f_port = Column(Integer, nullable=True)
    error = Column(String(300), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    altitude = Column(Float, nullable=True)
    app_name = Column(String(100), nullable=True)
    dev_name = Column(String(100), nullable=True)

    def to_json(self):
        return {
            'id': self.id,
            'date': "{}".format(self.date),
            'topic': self.topic,
            'data_collector_id': self.data_collector_id,
            'organization_id': self.organization_id,
            'gateway': self.gateway,
            'tmst': self.tmst,
            'chan': self.chan,
            'rfch': self.rfch,
            'seqn': self.seqn,
            'opts': self.opts,
            'port': self.port,
            'freq': self.freq,
            'stat': self.stat,
            'modu': self.modu,
            'datr': self.datr,
            'codr': self.codr,
            'lsnr': self.lsnr,
            'rssi': self.rssi,
            'size': self.size,
            'data': self.data,
            'm_type': self.m_type,
            'major': self.major,
            'mic': self.mic,
            'join_eui': self.join_eui,
            'dev_eui': self.dev_eui,
            'dev_nonce': self.dev_nonce,
            'dev_addr': self.dev_addr,
            'adr': self.adr,
            'ack': self.ack,
            'adr_ack_req': self.adr_ack_req,
            'f_pending': self.f_pending,
            'class_b': self.class_b,
            'f_count': self.f_count,
            'f_opts': self.f_opts,
            'f_port': self.f_port,
            'error': self.error
        }

    @classmethod
    def find(cls, organization_id, mtype, since, until, page, size):
        query = cls.query.filter(cls.organization_id == organization_id)
        if since:
            query = query.filter(cls.date >= since)
        if until:
            query = query.filter(cls.date <= until)
        if mtype:
            query = query.filter(cls.m_type == mtype)
        query = query.order_by(desc(cls.date))
        if page is not None and size:
            query = query.limit(size).offset(page*size)
        return query.all()

    @classmethod
    def count_by_date(cls, organization_id, mtype, since, until):
        query = db.session.query(func.date(cls.date).label('date'), func.count(1).label('count'))\
            .filter(cls.organization_id == organization_id)
        if since:
            query = query.filter(cls.date >= since)
        if until:
            query = query.filter(cls.date <= until)
        if mtype:
            query = query.filter(cls.m_type == mtype)
        query = query.group_by(func.date(cls.date))
        return query.all()
    
    @classmethod
    def count_by_hour(cls, organization_id, mtype, since, until):
        query = db.session.query(func.date_trunc('hour', cls.date).label('hour'), func.count(1).label('count'))\
            .filter(cls.organization_id == organization_id)
        if since:
            query = query.filter(cls.date >= since)
        if until:
            query = query.filter(cls.date <= until)
        if mtype:
            query = query.filter(cls.m_type == mtype)
        query = query.group_by(func.date_trunc('hour', cls.date))
        return query.all()

    @classmethod
    def find_max_by_organization_id(cls, organization_id, min_date):
        query = db.session.query(cls.data_collector_id.label('data_collector_id'), func.max(cls.date).label('date'))
        query = query.filter(cls.date > min_date, cls.organization_id == organization_id)
        query = query.group_by(cls.data_collector_id)
        return query.all()


class DeviceAuthData(db.Model):
    __tablename__ = 'device_auth_data'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    join_request = Column(String(200), nullable=True)
    join_accept = Column(String(200), nullable=True)
    apps_key = Column(String(32), nullable=True)
    nwks_key = Column(String(32), nullable=True)
    data_collector_id = Column(BigInteger, ForeignKey("data_collector.id"), nullable=False)
    organization_id = Column(BigInteger, ForeignKey("organization.id"), nullable=False)
    app_key_id = Column(BigInteger, ForeignKey("app_key.id"), nullable=False)
    device_id = Column(BigInteger, ForeignKey("device.id"), nullable=True)
    device_session_id = Column(BigInteger, ForeignKey("device_session.id"), nullable=True)


class Params(db.Model):
    __tablename__ = 'params'
    id = Column(Integer, primary_key=True, autoincrement=True)
    url_base = Column(String(120), nullable=False)

    @classmethod
    def get_url_base(cls):
        # print("db query")
        return cls.query.one().url_base


class QuarantineResolutionReasonType(Enum):
    MANUAL = 'MANUAL'
    AUTOMATIC = 'AUTOMATIC'


class QuarantineResolutionReason(db.Model):
    __tablename__ = "quarantine_resolution_reason"
    # region fields
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    type = Column(SQLEnum(QuarantineResolutionReasonType))
    name = Column(String(80), nullable=False)
    description = Column(String(200), nullable=True)

    # endregion

    @classmethod
    def find_by_id(cls, id):
        return cls.query.filter(cls.id == id).first()

    @classmethod
    def find_by_type(cls, type):
        return cls.query.filter(cls.type == type).first()


class Quarantine(db.Model):
    __tablename__ = "quarantine"
    #region fields
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    organization_id = Column(BigInteger, ForeignKey("organization.id"), nullable=False)
    # alert relationship
    alert_id = Column(BigInteger, ForeignKey("alert.id"), nullable=False)
    # since when is this device/alert in quarantine
    since = Column(DateTime(timezone=True), nullable=False)
    # last time the condition for quarantine was checked
    last_checked = Column(DateTime(timezone=True), nullable=True)
    # when was resolved, if applicable
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    # who resolved the quarantine, if applicable
    resolved_by_id = Column(BigInteger, ForeignKey("iot_user.id"), nullable=True)
    # resolution reason relationship, if resolved. Null if not
    resolution_reason_id = Column(BigInteger, ForeignKey("quarantine_resolution_reason.id"), nullable=True)
    # resolution comment (optional)
    resolution_comment = Column(String(1024), nullable=True)
    # quarantine parameters (optional)
    parameters = Column(String(4096), nullable=True)
    # device relationship
    device_id = Column(BigInteger, ForeignKey("device.id"))

    alert = relationship("Alert", lazy="joined")
    #endregion

    def to_list_json(self):
        data_collector = DataCollector.find_by_id(self.alert.data_collector_id)
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'alert': self.alert.to_json(),
            'alert_type': self.alert.alert_type.to_json(),
            'device_id': self.device_id,
            'data_collector_id': data_collector.id,
            'data_collector_name': data_collector.name,
            'parameters': json.loads(self.parameters if self.parameters is not None else '{}'),
            'since': f'{self.since}' if self.since else None,
            'last_checked': f'{self.last_checked}' if self.last_checked else None,
            'resolved_at': f'{self.resolved_at}' if self.resolved_at else None,
            'resolved_by_id': self.resolved_by_id,
            'resolution_reason_id': self.resolution_reason_id,
            'resolution_comment': self.resolution_comment
        }

    def db_insert(self):
        db.session.add(self)
        db.session.commit()

    def db_update(cls):
        db.session.commit()

    def db_delete(self):
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def find_by_id(cls, id):
        return cls.query.filter(cls.id == id).first()

    @classmethod
    def get_list_query(cls, organization_id, since, until, alert_types, devices, risks, data_collectors):
        query = cls.query.filter(cls.organization_id == organization_id).filter(cls.resolved_at.is_(None))\
            .filter(DataCollector.deleted_at.is_(None)).join(Alert).join(AlertType).join(DataCollector)

        if since:
            query = query.filter(cls.since >= since)
        if until:
            query = query.filter(cls.since <= until)

        if alert_types and len(alert_types) > 0:
            query = query.filter(AlertType.id.in_(alert_types))

        if risks and len(risks) > 0:
            query = query.filter(AlertType.risk.in_(risks))

        if devices and len(devices) > 0:
            query = query.filter(cls.device_id.in_(devices))

        if data_collectors and len(data_collectors) > 0:
            query = query.filter(Alert.data_collector_id.in_(data_collectors))
        return query

    @classmethod
    def find(cls, organization_id, since, until, alert_types, devices, risks, data_collectors, order_by, page, size):
        query = cls.get_list_query(organization_id, since, until, alert_types, devices, risks, data_collectors)

        if order_by:
            order_field = order_by[0]
            order_direction = order_by[1]
            if 'ASC' == order_direction:
                query = query.order_by(asc(getattr(cls, order_field)))
            else:
                query = query.order_by(desc(getattr(cls, order_field)))
        else:
            query = query.order_by(desc(cls.since), Alert.device_id, Alert.data_collector_id)

        if page and size:
            return query.paginate(page=page, per_page=size, error_out=config.ERROR_OUT, max_per_page=config.MAX_PER_PAGE)

        return query.all()

    @classmethod
    def count(cls, organization_id, since, until, alert_types, devices, risks, data_collectors):
        query = cls.get_list_query(organization_id, since, until, alert_types, devices, risks, data_collectors)
        # this generates a select count(*) from xxx where yyy instead of select count(*) from (select yyy from xxx)
        # see https://gist.github.com/hest/8798884
        count_q = query.statement.with_only_columns([func.count(func.distinct(Quarantine.id))])
        return query.session.execute(count_q).scalar()

    @classmethod
    def count_by_data_collector(cls, organization_id, since, until, alert_types, devices, risks, data_collectors):
        query = cls.get_list_query(organization_id, since, until, alert_types, devices, risks, data_collectors)
        count_query = query.with_entities(func.count(func.distinct(Quarantine.id)).label('quarantine_count'), Alert.data_collector_id.label('data_collector_id'), DataCollector.name.label('data_collector_name'))
        return count_query.group_by('data_collector_id','data_collector_name').all()

    @classmethod
    def count_by_risk(cls, organization_id, since, until, alert_types, devices, risks, data_collectors):
        query = cls.get_list_query(organization_id, since, until, alert_types, devices, risks, data_collectors)
        count_query = query.with_entities(func.count(func.distinct(Quarantine.id)).label('quarantine_count'), AlertType.risk.label('alert_type_risk'))
        return count_query.group_by('alert_type_risk').all()

    @classmethod
    def count_by_alert_type(cls, organization_id, since, until, alert_types, devices, risks, data_collectors):
        query = cls.get_list_query(organization_id, since, until, alert_types, devices, risks, data_collectors)
        count_query = query.with_entities(func.count(func.distinct(Quarantine.id)).label('quarantine_count'), AlertType.id.label('alert_type_id'), AlertType.name.label('alert_type_name'))
        return count_query.group_by('alert_type_id','alert_type_name').all()

    @classmethod
    def count_devices(cls, organization_id, since, until, alert_types, devices, risks, data_collectors):
        query = cls.get_list_query(organization_id, since, until, alert_types, devices, risks, data_collectors)
        count_q = query.statement.with_only_columns([func.count(func.distinct(case([(Alert.device_id != None, Alert.device_id)], else_=Alert.device_session_id)))])
        return query.session.execute(count_q).scalar()

    @classmethod
    def count_devices_by_hour(cls, organization_id, since, until, alert_types, devices, risks, data_collectors):
        query = cls.get_list_query(organization_id, since, until, alert_types, devices, risks, data_collectors)
        count_query = query.with_entities(func.count(func.distinct(case([(Alert.device_id != None, Alert.device_id)], else_=Alert.device_session_id))).label('device_count'),func.date_trunc('hour', cls.since).label('hour'))
        return count_query.group_by('hour').all()

    @classmethod
    def count_devices_by_date(cls, organization_id, since, until, alert_types, devices, risks, data_collectors):
        query = cls.get_list_query(organization_id, since, until, alert_types, devices, risks, data_collectors)
        count_query = query.with_entities(func.count(func.distinct(case([(Alert.device_id != None, Alert.device_id)], else_=Alert.device_session_id))).label('device_count'),func.date(cls.since).label('date'))
        return count_query.group_by('date').all()

    @classmethod
    def remove_from_quarantine_by_alert(cls, alert, res_reason_id, res_comment):
        cls.remove_from_quarantine(alert.alert_type.id, alert.device_id, alert.device_session_id, alert.data_collector_id, res_reason_id, res_comment)

    @classmethod
    def remove_from_quarantine_manually(cls, id, user_id, res_comment):
        qRec = cls.find_by_id(id)
        if not qRec:
            raise RuntimeError(f'Quarantine record with id {id} not found')
        if qRec.resolved_at is not None:
            raise RuntimeError(f'Quarantine is already resolved')
        reason = QuarantineResolutionReason.find_by_type(QuarantineResolutionReasonType.MANUAL)
        if not reason:
            raise RuntimeError(f'Manual quarantine resolution type not found')
        qRec.resolved_at = datetime.datetime.now()
        qRec.resolved_by_id = user_id
        qRec.resolution_reason_id = reason.id
        qRec.resolution_comment = res_comment
        qRec.db_update()

    @classmethod
    def remove_from_quarantine(cls, alert_type_id, device_id, device_session_id, data_collector_id, res_reason_id, res_comment):
        qrec = cls.find_open_by_type_dev_coll(alert_type_id, device_id, device_session_id, data_collector_id)
        if qrec:
            qrec.resolved_at = datetime.datetime.now()
            qrec.resolution_reason_id = res_reason_id
            qrec.resolution_comment = res_comment
            qrec.db_update()


# Gets the list of collector ids that a user can see - the ones that are assigned to that user.
# Takes a 'collectors_filter_id_strings' param that when is present acts as a filter on top of the visible collectors.
# Raises a ValueError when a collector id in the filtering param is not visible by the user.
def get_user_collector_ids(user, collectors_filter_id_strings=None):

    if config.ASSIGN_COLLECTOR_TO_USER_ENABLED:
        admin_user = is_admin_user(user.id)
    else:
        # If the feature is not enabled then behave as if the user was an admin - all collectors are visible.
        admin_user = True

    if collectors_filter_id_strings and len(collectors_filter_id_strings) > 0:

        # Filtering is on.
        collectors_from_filter = list(map(lambda user_id: int(user_id), collectors_filter_id_strings))
        if not admin_user:
            # Non-admin user -> check that the user has access to all the collectors in the filter.
            collectors_for_user = list(map(lambda c: c.id, user.collectors))
            all_requested_collectors_accessible = set(collectors_from_filter).issubset(collectors_for_user)
            if not all_requested_collectors_accessible:
                raise ValueError('The user does not have access to all the data collectors in the filter.')
        collectors = collectors_from_filter

    else:

        # No filtering.
        if admin_user:
            # Admin user -> list data from all the collectors in the organization.
            collectors = []
        else:
            # Non-admin user -> list data from the collectors that are assigned to the user.
            if user.collectors and len(user.collectors) > 0:
                collectors = list(map(lambda u: u.id, user.collectors))
            else:
                collectors = [-1]  # The user does not have access to any collector.

    return collectors


# verify if specified username belongs to user with role 'User_Admin'
def is_admin_user(user_id):
    role_id = UserRole.find_by_role_name(RoleTypes.User_Admin.value).id
    if not role_id:
        return None
    if UserToUserRole.find_by_user_id_and_user_role_id(user_id, role_id):
        return True
    else:
        return False


# verify if specified username is system
def is_system_user(user_id):
    role_id = UserRole.find_by_role_name(RoleTypes.System.value).id
    if not role_id:
        return None
    if UserToUserRole.find_by_user_id_and_user_role_id(user_id, role_id):
        return True
    else:
        return False
