from flask import request
from flask_restful import Resource
from flask_jwt_extended import get_jwt_claims

import iot_logging, calendar, json
log = iot_logging.getLogger(__name__)

from collections import namedtuple

from iot_api.user_api.model import User
from iot_api.user_api.Utils import is_system
from iot_api.user_api.JwtUtils import admin_regular_allowed
from iot_api.user_api.repository import ResourceUsageRepository, TagRepository, PacketRepository
from iot_api.user_api import Error

class ResourceUsageInformationAPI(Resource):
    """ Endpoint to get the resource usage of an asset of a given type
    Request parameters:
        - asset_type: type of requested asset (can be device or gateway).
        - asset_id: database id of the asset
    Returns:
        - JSON with requested resource usage information.
    """
    @admin_regular_allowed
    def get(self, asset_type, asset_id):
        organization_id = get_jwt_claims().get('organization_id')
        asset = ResourceUsageRepository.get_with(asset_id, asset_type,  organization_id)

        PacketsInfo = namedtuple('PacketsInfo', ['up', 'down', 'lost'])
        packet_counts = PacketsInfo(
            asset.npackets_up,
            asset.npackets_down,
            int(round(asset.packet_loss * asset.npackets_up)) if asset.packet_loss is not None else 0,
        )

        uptime = asset.npackets_up * asset.activity_freq if asset.activity_freq else 0

        response = {
            'id': asset.id,
            'hex_id': asset.hex_id,
            'type': asset.type,
            'name': asset.name,
            'data_collector': asset.data_collector,
            'app_name': asset.app_name,
            'connected': asset.connected,
            'last_activity': calendar.timegm(asset.last_activity.timetuple()),
            'activity_freq': asset.activity_freq,
            'packets_up': buildPacketsInfo(uptime, packet_counts.up, sum(list(packet_counts))),
            'packets_down': buildPacketsInfo(uptime, packet_counts.down, sum(list(packet_counts))),
            'packets_lost': buildPacketsInfo(uptime, packet_counts.lost, sum(list(packet_counts))) if asset.packet_loss is not None else None,
            'max_rssi': asset.max_rssi,
            'max_lsnr': asset.max_lsnr,
            'ngateways_connected_to': asset.ngateways_connected_to,
            'payload_size': asset.payload_size,
            'tags': [{
                "id": tag.id,
                "name": tag.name,
                "color": tag.color
            } for tag in TagRepository.list_asset_tags(asset_id, asset_type, organization_id)],
            'last_packets_list': [packet.to_json() for packet in PacketRepository.get_with(ids_list=json.loads(asset.last_packets_list))] if asset_type == 'device' else None
        }

        return response, 200

class ResourceUsageListAPI(Resource):
    """ Endpoint to list assets (devices + gateways)
    Request parameters (all optional):
        - page: for pagination.
        - size: for pagination.
        - asset_type: for filtering, count only this type of asset ("device" or "gateway").
        - asset_status: for filtering, count only assets with this status ("connected" or "disconnected").
        - gateway_ids[]: for filtering, count only the assets connected to ANY one of these gateways.
        - device_ids[]: for filtering, list only the assets related to ANY of these devices
        - min_signal_strength: for filtering, count only the assets with signal strength not lower than this value (dBm)
        - max_signal_strength: for filtering, count only the assets with signal strength not higher than this value (dBm)
        - min_packet_loss: for filtering, count only the assets with packet loss not lower than this value (percentage)
        - max_packet_loss: for filtering, count only the assets with packet loss not higher than this value (percentage)
    Returns:
        - JSON with list of assets and their resource usage (see code for more details about the fields).
    """
    @admin_regular_allowed
    def get(self):
        organization_id = get_jwt_claims().get('organization_id')
        page = request.args.get('page', default=1, type=int)
        size = request.args.get('size', default=20, type=int)

        results = ResourceUsageRepository.list_all(
            organization_id = organization_id,
            page = page, size = size,
            asset_type = request.args.get('asset_type', default=None, type=str),
            asset_status = request.args.get('asset_status', default=None, type=str),
            gateway_ids = request.args.getlist('gateway_ids[]'),
            device_ids = request.args.getlist('device_ids[]'),
            min_signal_strength = request.args.get('min_signal_strength', default = None, type=int),
            max_signal_strength = request.args.get('max_signal_strength', default = None, type=int),
            min_packet_loss = request.args.get('min_packet_loss', default = None, type=int),
            max_packet_loss = request.args.get('max_packet_loss', default = None, type=int)
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
            'max_rssi': dev.max_rssi,
            'max_lsnr': dev.max_lsnr,
            'payload_size':dev.payload_size,
            'ngateways_connected_to':dev.ngateways_connected_to
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

class ResourceUsagePerStatusCountAPI(Resource):
    """ Endpoint to count assets (devices+gateways) grouped by status (connected/disconnected).
    Request parameters: 
        - asset_type: for filtering, count only this type of asset ("device" or "gateway").
        - asset_status: for filtering, count only assets with this status ("connected" or "disconnected").
        - gateway_ids[]: for filtering, count only the assets connected to ANY one of these gateways.
        - device_ids[]: for filtering, list only the assets related to ANY of these devices
        - min_signal_strength: for filtering, count only the assets with signal strength not lower than this value (dBm)
        - max_signal_strength: for filtering, count only the assets with signal strength not higher than this value (dBm)
        - min_packet_loss: for filtering, count only the assets with packet loss not lower than this value (percentage)
        - max_packet_loss: for filtering, count only the assets with packet loss not higher than this value (percentage)
    Returns:
        - A list of JSONs, where each JSON has three fields: id, name, count. (id = name = 'connected'/'disconnected')
    """
    @admin_regular_allowed
    def get(self):
        organization_id = get_jwt_claims().get('organization_id')   
        
        groups = ResourceUsageRepository.count_per_status(
            organization_id = organization_id,
            asset_type = request.args.get('asset_type', default=None, type=str),
            asset_status = request.args.get('asset_status', default=None, type=str),
            gateway_ids = request.args.getlist('gateway_ids[]'),
            device_ids = request.args.getlist('device_ids[]'),
            min_signal_strength = request.args.get('min_signal_strength', default = None, type=int),
            max_signal_strength = request.args.get('max_signal_strength', default = None, type=int),
            min_packet_loss = request.args.get('min_packet_loss', default = None, type=int),
            max_packet_loss = request.args.get('max_packet_loss', default = None, type=int)
        )
        return {
            'total_count': sum(group['count'] for group in groups),
            'groups': groups
        }, 200

class ResourceUsagePerGatewayCountAPI(Resource):
    """ Endpoint to count assets (devices+gateways) grouped by gateway.
    Request parameters: 
        - asset_type: for filtering, count only this type of asset ("device" or "gateway").
        - asset_status: for filtering, count only assets with this status ("connected" or "disconnected").
        - gateway_ids[]: for filtering, count only the assets connected to ANY one of these gateways.
        - device_ids[]: for filtering, list only the assets related to ANY of these devices
        - min_signal_strength: for filtering, count only the assets with signal strength not lower than this value (dBm)
        - max_signal_strength: for filtering, count only the assets with signal strength not higher than this value (dBm)
        - min_packet_loss: for filtering, count only the assets with packet loss not lower than this value (percentage)
        - max_packet_loss: for filtering, count only the assets with packet loss not higher than this value (percentage)
    Returns:
        - A list of JSONs, where each JSON has three fields: id, name, count. (name = hex_id)
    """
    @admin_regular_allowed
    def get(self):
        organization_id = get_jwt_claims().get('organization_id')

        groups = ResourceUsageRepository.count_per_gateway(
            organization_id = organization_id,
            asset_type = request.args.get('asset_type', default=None, type=str),
            asset_status = request.args.get('asset_status', default=None, type=str),
            gateway_ids = request.args.getlist('gateway_ids[]'),
            device_ids = request.args.getlist('device_ids[]'),
            min_signal_strength = request.args.get('min_signal_strength', default = None, type=int),
            max_signal_strength = request.args.get('max_signal_strength', default = None, type=int),
            min_packet_loss = request.args.get('min_packet_loss', default = None, type=int),
            max_packet_loss = request.args.get('max_packet_loss', default = None, type=int)
        )
        return {
            'total_count': sum(group['count'] for group in groups),
            'groups': groups
        }, 200

class ResourceUsagePerSignalStrengthCountAPI(Resource):
    """ Endpoint to count assets (devices+gateways) grouped by signal strength.
    Request parameters: 
        - asset_type: for filtering, count only this type of asset ("device" or "gateway").
        - asset_status: for filtering, count only assets with this status ("connected" or "disconnected").
        - gateway_ids[]: for filtering, count only the assets connected to ANY one of these gateways.
        - device_ids[]: for filtering, list only the assets related to ANY of these devices
        - min_signal_strength: for filtering, count only the assets with signal strength not lower than this value (dBm)
        - max_signal_strength: for filtering, count only the assets with signal strength not higher than this value (dBm)
        - min_packet_loss: for filtering, count only the assets with packet loss not lower than this value (percentage)
        - max_packet_loss: for filtering, count only the assets with packet loss not higher than this value (percentage)
    Returns:
        - A list of JSONs, where each JSON has the following structure:
            'id': {
                'min_signal_strength': int,
                'max_signal_strength': int
            },
            'name': 'Unusable'/'Very weak'/'Weak'/'Okay'/'Great'/'Excellent',
            'count': int
    """
    @admin_regular_allowed
    def get(self):
        organization_id = get_jwt_claims().get('organization_id')

        groups = ResourceUsageRepository.count_per_signal_strength(
            organization_id = organization_id,
            asset_type = request.args.get('asset_type', default=None, type=str),
            asset_status = request.args.get('asset_status', default=None, type=str),
            gateway_ids = request.args.getlist('gateway_ids[]'),
            device_ids = request.args.getlist('device_ids[]'),
            min_signal_strength = request.args.get('min_signal_strength', default = None, type=int),
            max_signal_strength = request.args.get('max_signal_strength', default = None, type=int),
            min_packet_loss = request.args.get('min_packet_loss', default = None, type=int),
            max_packet_loss = request.args.get('max_packet_loss', default = None, type=int)
        )
        # Make the ids a JSON object instead of a tuple
        for signal_range in groups:
            signal_range['id'] = {
                'min_signal_strength': signal_range['id'][0],
                'max_signal_strength': signal_range['id'][1]
            }

        return {
            'total_count': sum(group['count'] for group in groups),
            'groups': groups
        }, 200

class ResourceUsagePerPacketLossCountAPI(Resource):
    """ Endpoint to count assets (devices+gateways) grouped by packet loss percentage
    Request parameters: 
        - asset_type: for filtering, count only this type of asset ("device" or "gateway").
        - asset_status: for filtering, count only assets with this status ("connected" or "disconnected").
        - gateway_ids[]: for filtering, count only the assets connected to ANY one of these gateways.
        - device_ids[]: for filtering, list only the assets related to ANY of these devices
        - min_signal_strength: for filtering, count only the assets with signal strength not lower than this value (dBm)
        - max_signal_strength: for filtering, count only the assets with signal strength not higher than this value (dBm)
        - min_packet_loss: for filtering, count only the assets with packet loss not lower than this value (percentage)
        - max_packet_loss: for filtering, count only the assets with packet loss not higher than this value (percentage)
    Returns:
        - A list of JSONs, where each JSON has the following structure:
            'id': {
                'min_packet_loss': int,
                'max_packet_loss': int
            },
            'name': '[0,10)'/'[10,20)'/.../'[80,90)'/'[90,100]',
            'count': int
    """
    @admin_regular_allowed
    def get(self):
        organization_id = get_jwt_claims().get('organization_id')

        groups = ResourceUsageRepository.count_per_packet_loss(
            organization_id = organization_id,
            asset_type = request.args.get('asset_type', default=None, type=str),
            asset_status = request.args.get('asset_status', default=None, type=str),
            gateway_ids = request.args.getlist('gateway_ids[]'),
            device_ids = request.args.getlist('device_ids[]'),
            min_signal_strength = request.args.get('min_signal_strength', default = None, type=int),
            max_signal_strength = request.args.get('max_signal_strength', default = None, type=int),
            min_packet_loss = request.args.get('min_packet_loss', default = None, type=int),
            max_packet_loss = request.args.get('max_packet_loss', default = None, type=int)
        )
        # Make the ids a JSON object instead of a tuple
        for loss_range in groups:
            loss_range['id'] = {
                'min_packet_loss': loss_range['id'][0],
                'max_packet_loss': loss_range['id'][1]
            }

        return {
            'total_count': sum(group['count'] for group in groups),
            'groups': groups
        }, 200
