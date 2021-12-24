from sqlalchemy import Column, BigInteger, Boolean, DateTime, String
from sqlalchemy.sql.schema import ForeignKey
from iot_api.user_api import db
from iot_api import config

class NotificationAdditionalTelephoneNumber(db.Model):
    id = Column(BigInteger, primary_key=True)
    phone = Column(String(30), nullable=False)
    token = Column(String(500), nullable=False)
    creation_date = Column(DateTime(timezone=False), nullable=False)
    active = Column(Boolean, nullable=False, default=False)
    user_id = Column(BigInteger, ForeignKey("iot_user.id"), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'phone': self.phone,
            'active': self.active
        }

    def delete(self):
        db.session.delete(self)
    
    def save(self):
        db.session.add(self)

    def update(self):
        db.session.commit()

    @classmethod
    def send_sms(cls,sns,alert_type,phones):
        for phone in phones:
            if config.SEND_SMS:             
                sns.publish(
                    PhoneNumber=phone,
                    Message=f'New notification from {config.BRAND_NAME}. There\'s a new alert: {alert_type.name}. You can check this accessing to {config.BRAND_URL}',
                )

    @classmethod
    def add_not_repeated(cls,user,phones):
        if user.phone and not user.phone in phones:
            phones.append(user.phone)
            additional = cls.find(user_id = user.id)
            for item in additional:
                if item.active and not item.phone in phones:
                    phones.append(item.phone)

    @classmethod
    def find(cls, user_id):
        return cls.query.filter(cls.user_id == user_id).all()

    @classmethod
    def find_one_by_token(cls, token):
        return cls.query.filter(cls.token == token).first()
