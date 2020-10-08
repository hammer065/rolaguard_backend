from sqlalchemy import Column, String, BigInteger, Integer

import iot_logging
from iot_api.user_api import db

LOG = iot_logging.getLogger(__name__)

class RowProcessed(db.Model):
    __tablename__ = 'row_processed'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    last_row = Column(Integer, nullable=False, default=0)
    analyzer = Column(String(20), nullable=False)