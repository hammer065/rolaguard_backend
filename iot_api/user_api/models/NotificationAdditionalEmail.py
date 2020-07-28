from sqlalchemy import Column, BigInteger, Boolean, DateTime, String
from sqlalchemy.sql.schema import ForeignKey
from iot_api.user_api import db

class NotificationAdditionalEmail(db.Model):
    id = Column(BigInteger, primary_key=True)
    email = Column(String(120), nullable=False)
    token = Column(String(500), nullable=False)
    creation_date = Column(DateTime(timezone=False), nullable=False)
    active = Column(Boolean, nullable=False, default=False)
    user_id = Column(BigInteger, ForeignKey("iot_user.id"), nullable=False)

    def delete(self):
        db.session.delete(self)

    def save(self):
        db.session.add(self)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'active': self.active
        }

    def update(self):
        db.session.commit()
    
    @classmethod
    def find(cls, user_id):
        return cls.query.filter(cls.user_id == user_id).all()

    @classmethod
    def find_one_by_token(cls, token):
        return cls.query.filter(cls.token == token).first()
