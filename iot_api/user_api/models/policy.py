from sqlalchemy import Integer, String, Column, BigInteger, Boolean, or_, and_
from sqlalchemy.sql.schema import ForeignKey
from iot_api.user_api import db
from sqlalchemy.orm import relationship, contains_eager, noload
from iot_api import config

from iot_api.user_api.models.DataCollector import DataCollector


class Policy(db.Model):
    __tablename__ = 'policy'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    items = relationship("PolicyItem", lazy="joined", cascade="all, delete-orphan")
    organization_id = Column(BigInteger, ForeignKey("organization.id"), nullable=True)
    is_default = Column(Boolean, nullable=False)
    data_collectors = relationship("DataCollector", lazy="joined")

    def to_dict(self):
        items = [item.to_dict() for item in self.items]
        data_collectors = [{'id': dc.id, 'name': dc.name} for dc in self.data_collectors]
        return {
            'id': self.id,
            'name': self.name,
            'isDefault': self.is_default,
            'organizationId': self.organization_id,
            'items': items,
            'dataCollectors': data_collectors 
        }

    def delete(self):
        db.session.delete(self)
        db.session.commit()
    
    def save(self):
        db.session.add(self)
        db.session.flush()

    @classmethod
    def commit(self):
        db.session.commit()

    @classmethod
    def rollback(self):
        db.session.rollback()

    @classmethod
    def find(cls, organization_id, name, distinct_id, page=None, size=None):
        query = cls.query.filter(or_(cls.organization_id == organization_id, cls.organization_id == None))

        # Not loading collectors here since any kind of join would enlarge the result set that is paginated.
        query = query.options(noload(Policy.data_collectors))

        if name:
            query = query.filter(cls.name == name)
        if distinct_id:
            query = query.filter(cls.id != distinct_id)
        return query.paginate(page=page, per_page=size, error_out=config.ERROR_OUT, max_per_page=config.MAX_PER_PAGE)

    @classmethod
    def find_with_collectors(cls, organization_id, name, distinct_id, page=None, size=None):
        results = cls.find(organization_id, name, distinct_id, page, size)

        policies = [policy for policy in results.items]
        for policy in policies:
            policy.data_collectors = DataCollector.find_by_organization_id_and_policy_id(organization_id, policy.id)

        # Returning the object from SQLAlchemy - not the 'policies' list - because the caller needs the metadata.
        return results

    @classmethod
    def find_one(cls, id, organization_id = None):
        if organization_id:
            query = cls.query.filter(cls.id==id)
            query = query.outerjoin(DataCollector, and_(DataCollector.organization_id == organization_id, DataCollector.policy_id == id, DataCollector.deleted_at == None)).options(contains_eager(Policy.data_collectors))
            result = query.all()
            if len(result) > 0:
                return result[0]
            else:
                return None
        return cls.query.get(id)
