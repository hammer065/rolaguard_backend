from sqlalchemy import Column, String, BigInteger, ForeignKey
from iot_api.user_api import db

class MqttTopic(db.Model):
    __tablename__ = "mqtt_topic"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    name = Column(String(120), nullable=False)
    data_collector_id = Column(BigInteger, ForeignKey("data_collector.id"), nullable=False)

    def to_json(self):
        return self.name

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def find_by_data_collector_id(cls, data_collector_id):
        return cls.query.filter_by(data_collector_id=data_collector_id).all()
