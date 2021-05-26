from sqlalchemy import Table, Column, ForeignKey, DateTime, String, BigInteger, Boolean

import iot_logging
from iot_api.user_api import db

LOG = iot_logging.getLogger(__name__)

class ChangeEmailRequests(db.Model):
    __tablename__ = "change_email_requests"

    id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey(
        "iot_user.id"), nullable=False)
    new_email = db.Column(db.String(120), nullable=False)
    old_email = db.Column(db.String(120), nullable=False)
    token = db.Column(db.String(500), nullable=False)
    creation_date = db.Column(db.DateTime(timezone=True), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)

    def to_json(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'new_email': self.new_email,
            'old_email': self.new_email,
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

    def rollback(self):
        db.session.rollback()

    @classmethod
    def find_by_token(cls, token):
        return cls.query.filter_by(token=token, active=True).first()

    @classmethod
    def find_active_tokens_by_user_id(cls, user_id):
        return cls.query.filter_by(user_id=user_id, active=True).all()

