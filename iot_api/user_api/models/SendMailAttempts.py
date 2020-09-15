from sqlalchemy import Table, Column, ForeignKey, DateTime, Integer

import iot_logging
from iot_api.user_api import db

LOG = iot_logging.getLogger(__name__)

class SendMailAttempts(db.Model):
    __tablename__ = "send_email_attempts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("iot_user.id"), nullable=False)
    attempts = Column(Integer, nullable=False, default=True)
    # last_attempt = db.Column(db.DateTime(timezone=True), nullable=False)

    def to_json(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'attempts': self.attempts
            # 'last_attempt': self.last_attempt
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
    def find_by_user(cls, user_id):
        return cls.query.filter_by(user_id=user_id).first()