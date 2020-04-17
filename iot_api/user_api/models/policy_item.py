from sqlalchemy import Integer, String, Column, BigInteger, Boolean
from sqlalchemy.sql.schema import ForeignKey
from iot_api.user_api import db
from sqlalchemy.orm import relationship
import json

class PolicyItem(db.Model):
    __tablename__ = 'policy_item'
    id = Column(Integer, primary_key=True, autoincrement=True)
    parameters = Column(String(4096), nullable=False)
    enabled = Column(Boolean, nullable=False)
    policy_id = Column(BigInteger, ForeignKey("policy.id", ondelete="CASCADE"), nullable=False)
    alert_type_code = Column(String(20), ForeignKey("alert_type.code"), nullable=False)
    alert_type = relationship("AlertType", lazy="joined")

    def to_dict(self):
        return {
            'id': self.id,
            'enabled': self.enabled,
            'parameters': json.loads(self.parameters),
            'alertTypeCode': self.alert_type_code,
            'alertType': self.alert_type.to_json()
        }

    def save(self):
        db.session.add(self)
        db.session.flush()

    @classmethod
    def find_one(cls, id):
        return cls.query.get(id)
