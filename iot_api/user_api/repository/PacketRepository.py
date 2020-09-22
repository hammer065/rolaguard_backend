import iot_logging, json
LOG = iot_logging.getLogger(__name__)

from iot_api.user_api import db
from iot_api.user_api.model import Packet, Gateway
from sqlalchemy import and_

def get_with(ids_list, min_rssi=None, max_rssi=None, min_lsnr=None, max_lsnr=None):
    """ Gets a list of packets from database
    Request parameters:
        - ids_list (required): return a packet if it's id is in the list
        - min_rssi: for filtering, return only packets with rssi not lower than this value
        - max_rssi: for filtering, return only packets with rssi not higher than this value
        - min_lsnr: for filtering, return only packets with lsnr not lower than this value
        - max_lsnr: for filtering, return only packets with lsnr not higher than this value
    """
    query = db.session.query(Packet, Gateway.id)\
            .filter(Packet.id.in_(ids_list))
    if min_rssi is not None:
        query = query.filter(Packet.rssi >= min_rssi)
    if max_rssi is not None:
        query = query.filter(Packet.rssi <= max_rssi)
    if min_lsnr is not None:
        query = query.filter(Packet.lsnr >= min_lsnr)
    if max_lsnr is not None:
        query = query.filter(Packet.lsnr <= max_lsnr)
    return query.join(Gateway, and_(Packet.gateway == Gateway.gw_hex_id, Packet.data_collector_id == Gateway.data_collector_id)).all()