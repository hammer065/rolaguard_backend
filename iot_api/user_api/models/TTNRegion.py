from sqlalchemy import Column, String, BigInteger
from iot_api.user_api import db

class TTNRegion(db.Model):
    __tablename__ = "ttn_region"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    region = Column(String(30), nullable=False, unique=True)
    name = Column(String(30), nullable=False, unique=True)

    def to_json(self):
        return {
            'id': self.id,
            'region': self.region,
            'name': self.name
        }

    @classmethod
    def find_one_by_region(cls, region):
        return cls.query.filter_by(region=region).first()

    @classmethod
    def find_one(cls, id):
        return cls.query.get(id)

    @classmethod
    def find_all(cls):
        return cls.query.all()
