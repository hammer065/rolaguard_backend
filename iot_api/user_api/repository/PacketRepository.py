import iot_logging, json
LOG = iot_logging.getLogger(__name__)

from iot_api.user_api import db
from iot_api.user_api.model import Packet

def get_with(ids_list):
    return db.session.query(Packet).filter(Packet.id.in_(ids_list)).all()