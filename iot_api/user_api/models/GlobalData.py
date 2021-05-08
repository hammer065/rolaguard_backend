from sqlalchemy import Column, String

import iot_logging
from iot_api.user_api import db

LOG = iot_logging.getLogger(__name__)

class GlobalData(db.Model):
    __tablename__ = "global_data"

    key = Column(String(120),nullable=False, primary_key=True)
    value = Column(String(300), nullable=False)

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
    def find_by_key(cls, key):
        return cls.query.filter_by(key=key).first()