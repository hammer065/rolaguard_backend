from flask import request
from flask_restful import Resource
from flask_jwt_extended import get_jwt_claims

import iot_logging, calendar, json, math
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
        - asset_type (required): type of requested asset (can be device or gateway).
        - asset_id (required): database id of the asset
        - min_rssi: for filtering packets list, return only packets with rssi not lower than this value
        - max_rssi: for filtering packets list, return only packets with rssi not higher than this value
        - min_lsnr: for filtering packets list, return only packets with lsnr not lower than this value
        - max_lsnr: for filtering packets list, return only packets with lsnr not higher than this value
    Returns:
        - JSON with requested resource usage information.
    """
    @admin_regular_allowed
    def get(self, asset_type, asset_id):
        organization_id = get_jwt_claims().get('organization_id')
        asset = ResourceUsageRepository.get_with(asset_id, asset_type,  organization_id)

        packets = None
        lsnr_values = None
        rssi_values = None
        if asset_type == 'device':
            temp_packets = PacketRepository.get_with(
                    ids_list=json.loads(asset.last_packets_list),
                    min_rssi = request.args.get('min_rssi', default = None, type=int),
                    max_rssi = request.args.get('max_rssi', default = None, type=int),
                    min_lsnr = request.args.get('min_lsnr', default = None, type=float),
                    max_lsnr = request.args.get('max_lsnr', default = None, type=float)
                )
            packets = []
            for packet, gw_id in temp_packets:
                to_add = packet.to_json()
                to_add.update({'gateway_id': gw_id})
                packets.append(to_add)
            lsnr_values = [packet['lsnr'] for packet in packets if packet['lsnr'] is not None]
            rssi_values = [packet['rssi'] for packet in packets if packet['rssi'] is not None]

        # Here the dev_addr is not returned to avoid a join between Device and DeviceSession,
        # since it is already reported in the inventory endpoint.
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
            'activity_freq_variance': asset.activity_freq_variance,
            'is_regular': asset_is_regular(asset),
            'packets_up': buildPacketsInfo(asset.PACKETS_UP, asset.PACKETS_UP+asset.PACKETS_DOWN+(asset.PACKETS_LOST or 0)),
            'packets_down': buildPacketsInfo(asset.PACKETS_DOWN, asset.PACKETS_UP+asset.PACKETS_DOWN+(asset.PACKETS_LOST or 0)),
            'packets_lost': buildPacketsInfo(asset.PACKETS_LOST, asset.PACKETS_UP+asset.PACKETS_DOWN+(asset.PACKETS_LOST or 0)) if asset.type == 'Device' else None,
            'retransmissions': asset.RETRANSMISSIONS,
            'join_requests': asset.JOIN_REQUESTS,
            'failed_join_requests': asset.FAILED_JOIN_REQUESTS,
            'max_rssi': asset.max_rssi,
            'max_lsnr': asset.max_lsnr,
            'ngateways_connected_to': asset.ngateways_connected_to,
            'payload_size': asset.payload_size,
            'tags': [{
                "id": tag.id,
                "name": tag.name,
                "color": tag.color
            } for tag in TagRepository.list_asset_tags(asset_id, asset_type, organization_id)],
            'last_packets_list': packets,
            'min_lsnr_packets': min(lsnr_values) if lsnr_values and len(lsnr_values) > 0 else None,
            'max_lsnr_packets': max(lsnr_values) if lsnr_values and len(lsnr_values) > 0 else None,
            'min_rssi_packets': min(rssi_values) if rssi_values and len(rssi_values) > 0 else None,
            'max_rssi_packets': max(rssi_values) if rssi_values and len(rssi_values) > 0 else None,
        }

        return response, 200

class ResourceUsageListAPI(Resource):
    """ Endpoint to list assets (devices + gateways)
    Request parameters (all optional):
        - page: for pagination.
        - size: for pagination.
        - asset_type: for filtering, count only this type of asset ("device" or "gateway").
        - asset_status: for filtering, count only assets with this status ("connected" or "disconnected").
        - data_collector_ids[]: for filtering, count only the assets belongs to these data collectors.
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
        order_by = request.args.getlist('order_by[]')

        asset_type = request.args.get('asset_type', default=None, type=str)

        min_signal_strength = request.args.get('min_signal_strength', default = None, type=int)
        max_signal_strength = request.args.get('max_signal_strength', default = None, type=int)
        min_packet_loss = request.args.get('min_packet_loss', default = None, type=int)
        max_packet_loss = request.args.get('max_packet_loss', default = None, type=int)

        if any(param is not None for param in [min_signal_strength, max_signal_strength, min_packet_loss, max_packet_loss]):
            if asset_type is None:
                asset_type = "device"
            elif asset_type == "gateway":
                return {
                        'assets': [],
                        'total_pages': 0,
                        'total_items': 0
                    }, 200

        results = ResourceUsageRepository.list_all(
            organization_id = organization_id,
            page = page, size = size,
            asset_type = asset_type,
            asset_status = request.args.get('asset_status', default=None, type=str),
            data_collector_ids=request.args.getlist('data_collector_ids[]'),
            gateway_ids = request.args.getlist('gateway_ids[]'),
            device_ids = request.args.getlist('device_ids[]'),
            min_signal_strength = min_signal_strength,
            max_signal_strength = max_signal_strength,
            min_packet_loss = min_packet_loss,
            max_packet_loss = max_packet_loss,
            order_by = order_by
        )

        assets = [{
            'id': dev.id,
            'hex_id': dev.hex_id,
            'dev_addr': dev.dev_addr,
            'type': dev.type,
            'name': dev.name,
            'data_collector': dev.data_collector,
            'app_name': dev.app_name,
            'connected': dev.connected,
            'last_activity': calendar.timegm(dev.last_activity.timetuple()),
            'activity_freq': dev.activity_freq,
            'activity_freq_variance': dev.activity_freq_variance,
            'is_regular': asset_is_regular(dev),
            'packets_up': buildPacketsInfo(dev.PACKETS_UP, dev.PACKETS_UP+dev.PACKETS_DOWN+(dev.PACKETS_LOST or 0)),
            'packets_down': buildPacketsInfo(dev.PACKETS_DOWN, dev.PACKETS_UP+dev.PACKETS_DOWN+(dev.PACKETS_LOST or 0)),
            'packets_lost': buildPacketsInfo(dev.PACKETS_LOST, dev.PACKETS_UP+dev.PACKETS_DOWN+(dev.PACKETS_LOST or 0)) if dev.type == 'Device' else None,
            'retransmissions': dev.RETRANSMISSIONS,
            'join_requests': dev.JOIN_REQUESTS,
            'failed_join_requests': dev.FAILED_JOIN_REQUESTS,
            'max_rssi': dev.max_rssi,
            'max_lsnr': dev.max_lsnr,
            'payload_size':dev.payload_size,
            'ngateways_connected_to':dev.ngateways_connected_to,
            'spread_factor':dev.spread_factor
        } for dev in results.items]

        response = {
            'assets': assets,
            'total_pages': results.pages,
            'total_items': results.total
        }

        return response, 200

def buildPacketsInfo(count, total):
    """ Helper function to calculate data related with packets received from an asset
    Request parameters (all required):
        - count: number of packets of the type (up, down, lost) to calculate data for
        - total: number of packets in total
    Returns:
        - JSON with packets related information (see code for more details about the fields).
    """
    return {
        'total': count,
        'percentage': 100*count/total if total else None
    }

def asset_is_regular(asset):
    params = json.loads(asset.policy_parameters or '{}')

    #Consider the asset as regular if irregularity cannot be checked
    if 'deviation_tolerance' not in params or asset.type == 'Gateway' or not asset.activity_freq:
        return True

    return math.sqrt(asset.activity_freq_variance)/asset.activity_freq <= params['deviation_tolerance']

class ResourceUsagePerStatusCountAPI(Resource):
    """ Endpoint to count assets (devices+gateways) grouped by status (connected/disconnected).
    Request parameters: 
        - asset_type: for filtering, count only this type of asset ("device" or "gateway").
        - asset_status: for filtering, count only assets with this status ("connected" or "disconnected").
        - data_collector_ids[]: for filtering, count only the assets belongs to these data collectors.
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

        asset_type = request.args.get('asset_type', default=None, type=str)

        min_signal_strength = request.args.get('min_signal_strength', default = None, type=int)
        max_signal_strength = request.args.get('max_signal_strength', default = None, type=int)
        min_packet_loss = request.args.get('min_packet_loss', default = None, type=int)
        max_packet_loss = request.args.get('max_packet_loss', default = None, type=int)

        if any(param is not None for param in [min_signal_strength, max_signal_strength, min_packet_loss, max_packet_loss]):
            if asset_type is None:
                asset_type = "device"
            elif asset_type == "gateway":
                asset_type = "none"
        
        groups = ResourceUsageRepository.count_per_status(
            organization_id = organization_id,
            asset_type = asset_type,
            asset_status = request.args.get('asset_status', default=None, type=str),
            data_collector_ids = request.args.getlist('data_collector_ids[]'),
            gateway_ids = request.args.getlist('gateway_ids[]'),
            device_ids = request.args.getlist('device_ids[]'),
            min_signal_strength = min_signal_strength,
            max_signal_strength = max_signal_strength,
            min_packet_loss = min_packet_loss,
            max_packet_loss = max_packet_loss
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
        - data_collector_ids[]: for filtering, count only the assets belongs to these data collectors.
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

        asset_type = request.args.get('asset_type', default=None, type=str)

        min_signal_strength = request.args.get('min_signal_strength', default = None, type=int)
        max_signal_strength = request.args.get('max_signal_strength', default = None, type=int)
        min_packet_loss = request.args.get('min_packet_loss', default = None, type=int)
        max_packet_loss = request.args.get('max_packet_loss', default = None, type=int)

        if any(param is not None for param in [min_signal_strength, max_signal_strength, min_packet_loss, max_packet_loss]):
            if asset_type is None:
                asset_type = "device"
            elif asset_type == "gateway":
                asset_type = "none"

        groups = ResourceUsageRepository.count_per_gateway(
            organization_id = organization_id,
            asset_type = asset_type,
            asset_status = request.args.get('asset_status', default=None, type=str),
            data_collector_ids = request.args.getlist('data_collector_ids[]'),
            gateway_ids = request.args.getlist('gateway_ids[]'),
            device_ids = request.args.getlist('device_ids[]'),
            min_signal_strength = min_signal_strength,
            max_signal_strength = max_signal_strength,
            min_packet_loss = min_packet_loss,
            max_packet_loss = max_packet_loss
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
        - data_collector_ids[]: for filtering, count only the assets belongs to these data collectors.
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

        asset_type = request.args.get('asset_type', default=None, type=str)

        min_signal_strength = request.args.get('min_signal_strength', default = None, type=int)
        max_signal_strength = request.args.get('max_signal_strength', default = None, type=int)
        min_packet_loss = request.args.get('min_packet_loss', default = None, type=int)
        max_packet_loss = request.args.get('max_packet_loss', default = None, type=int)

        if any(param is not None for param in [min_signal_strength, max_signal_strength, min_packet_loss, max_packet_loss]):
            if asset_type is None:
                asset_type = "device"
            elif asset_type == "gateway":
                asset_type = "none"

        groups = ResourceUsageRepository.count_per_signal_strength(
            organization_id = organization_id,
            asset_type = asset_type,
            asset_status = request.args.get('asset_status', default=None, type=str),
            data_collector_ids = request.args.getlist('data_collector_ids[]'),
            gateway_ids = request.args.getlist('gateway_ids[]'),
            device_ids = request.args.getlist('device_ids[]'),
            min_signal_strength = min_signal_strength,
            max_signal_strength = max_signal_strength,
            min_packet_loss = min_packet_loss,
            max_packet_loss = max_packet_loss
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
        - data_collector_ids[]: for filtering, count only the assets belongs to these data collectors.
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

        asset_type = request.args.get('asset_type', default=None, type=str)

        min_signal_strength = request.args.get('min_signal_strength', default = None, type=int)
        max_signal_strength = request.args.get('max_signal_strength', default = None, type=int)
        min_packet_loss = request.args.get('min_packet_loss', default = None, type=int)
        max_packet_loss = request.args.get('max_packet_loss', default = None, type=int)

        if any(param is not None for param in [min_signal_strength, max_signal_strength, min_packet_loss, max_packet_loss]):
            if asset_type is None:
                asset_type = "device"
            elif asset_type == "gateway":
                asset_type = "none"

        groups = ResourceUsageRepository.count_per_packet_loss(
            organization_id = organization_id,
            asset_type = asset_type,
            asset_status = request.args.get('asset_status', default=None, type=str),
            data_collector_ids = request.args.getlist('data_collector_ids[]'),
            gateway_ids = request.args.getlist('gateway_ids[]'),
            device_ids = request.args.getlist('device_ids[]'),
            min_signal_strength = min_signal_strength,
            max_signal_strength = max_signal_strength,
            min_packet_loss = min_packet_loss,
            max_packet_loss = max_packet_loss
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
