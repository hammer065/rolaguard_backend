from flask import jsonify, request
from flask_restful import Resource
from flask_jwt_extended import get_jwt_identity, jwt_required

import json

from iot_api.user_api.model import User
from iot_api.user_api.models.DataCollectorLogEvent import DataCollectorLogEvent
from iot_api.user_api.models.DataCollector import DataCollector

from iot_api.user_api.Utils import is_admin_user, is_regular_user

class DataCollectorLogEventListResource(Resource):

    @jwt_required
    def get(self, data_collector_id):
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)        
        data_collector = DataCollector.find_by_id(data_collector_id)

        if not data_collector:
            return None, 404

        if not user or data_collector.organization_id != user.organization_id or not is_admin_user(user.id) and not is_regular_user(user.id):
            return [], 403

        page = request.args.get('page', default=1, type=int)
        size = request.args.get('size', default=20, type=int)

        result = DataCollectorLogEvent.find(data_collector_id, page, size)
        headers = {'total-pages': result.pages, 'total-items': result.total}
        events = [event.to_dict() for event in result.items]

        return events, 200, headers

