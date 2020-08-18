from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity

import iot_logging, calendar
log = iot_logging.getLogger(__name__)

from collections import namedtuple

from iot_api.user_api.model import User
from iot_api.user_api.Utils import is_system
from iot_api.user_api.repository import ResourceUsageRepository
from iot_api.user_api import Error


class ResourceUsageListAPI(Resource):
    """ Endpoint to list assets (devices + gateways)
    Request parameters (all optional):
        - page: for pagination.
        - size: for pagination.
        - gateway_ids[]: for filtering, list only the assets connected to ANY one of these gateways.
        - data_collector_ids[]: for filtering, list only the assest related to ANY of these data collectors.
        - asset_type: for filtering, list only this type of asset ("device" or "gateway").
    Returns:
        - JSON with list of assets and their resource usage (see code for more details about the fields).
    """
    @jwt_required
    def get(self):
        user = User.find_by_username(get_jwt_identity())
        if not user or is_system(user.id):
            raise Error.Forbidden()

        organization_id = user.organization_id
        page = request.args.get('page', default=1, type=int)
        size = request.args.get('size', default=20, type=int)

        results = ResourceUsageRepository.list_all(
            organization_id=organization_id,
            page=page, size=size,
            gateway_ids=request.args.getlist('gateway_ids[]'),
            data_collector_ids=request.args.getlist('data_collector_ids[]'),
            asset_type=request.args.get('asset_type', type=str)
        )

        PacketsInfo = namedtuple('PacketsInfo', ['up', 'down', 'lost'])
        packet_counts = [PacketsInfo(
            dev.npackets_up,
            dev.npackets_down,
            int(round(dev.packet_loss * dev.npackets_up)) if dev.packet_loss is not None else 0,
        ) for dev in results.items]

        uptimes = [dev.npackets_up * dev.activity_freq if dev.activity_freq else 0 for dev in results.items]

        assets = [{
            'id': dev.id,
            'hex_id': dev.hex_id,
            'type': dev.type,
            'name': dev.name,
            'data_collector': dev.data_collector,
            'app_name': dev.app_name,
            'connected': dev.connected,
            'last_activity': calendar.timegm(dev.last_activity.timetuple()),
            'activity_freq': dev.activity_freq,
            'packets_up': buildPacketsInfo(uptime, packets.up, sum(list(packets))),
            'packets_down': buildPacketsInfo(uptime, packets.down, sum(list(packets))),
            'packets_lost': buildPacketsInfo(uptime, packets.lost, sum(list(packets))) if dev.packet_loss is not None else None,
            'max_rssi': dev.max_rssi
        } for dev, packets, uptime in zip(results.items, packet_counts, uptimes)]
        response = {
            'assets': assets,
            'total_pages': results.pages,
            'total_items': results.total
        }
        return response, 200

def buildPacketsInfo(uptime, count, total):
    """ Helper function to calculate data related with packets received from an asset
    Request parameters (all required):
        - uptime: time since asset is connected in seconds
        - count: number of packets of the type (up, down, lost) to calculate data for
        - total: number of packets in total
    Returns:
        - JSON with packets related information (see code for more details about the fields).
    """
    secs_bw_packets = uptime/count if count else None
    return {
        'total': count,
        'per_minute': 60/secs_bw_packets if secs_bw_packets else 0,
        'per_hour': 60*60/secs_bw_packets if secs_bw_packets else 0,
        'per_day': 24*60*60/secs_bw_packets if secs_bw_packets else 0,
        'percentage': 100*count/total if total else None
    }
