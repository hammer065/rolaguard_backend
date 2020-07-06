from sqlalchemy import Column, String, BigInteger
from iot_api.user_api import db

class DataCollectorType(db.Model):
    __tablename__ = "data_collector_type"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    type = Column(String(30), nullable=False, unique=True)
    name = Column(String(30), nullable=False, unique=True)

    def to_json(self):
        return {
            'id': self.id,
            'type': self.type,
            'name': self.name
        }

    @classmethod
    def find_one_by_name(cls, name):
        return cls.query.filter_by(name=name).first()

    @classmethod
    def find_one(cls, id):
        return cls.query.get(id)

    @classmethod
    def find_all(cls):
        return cls.query.all()
