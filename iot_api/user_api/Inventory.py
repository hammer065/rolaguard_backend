import json
from flask import request, abort, jsonify
from flask_jwt_extended import get_jwt_identity
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity

import iot_logging
LOG = iot_logging.getLogger(__name__)

from sqlalchemy.sql import select, expression, text

from iot_api.user_api import db
from iot_api.user_api.model import User
from iot_api.user_api.Utils import is_admin_user, is_regular_user
from iot_api.user_api.model import Device, Gateway, DataCollectorToDevice
from iot_api.user_api.models import DataCollector


class DeviceInventoryAPI(Resource):
    @jwt_required
    def get(self):
        try:
            user_identity = get_jwt_identity()
            user = User.find_by_username(user_identity)
            if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
                return abort(403, error='forbidden access')

            organization_id = user.organization_id
            page = request.args.get('page', default=1, type=int)
            size = request.args.get('size', default=20, type=int)

            s1 = select([Device.dev_eui.label('id'),
             expression.literal_column('\'Device\'').label('type'),
             Device.name,
             DataCollector.name.label('data_collector'),
             Device.vendor]).\
                 where(Device.organization_id == 4).\
                 where(Device.id==DataCollectorToDevice.device_id).\
                 where(DataCollector.id==DataCollectorToDevice.data_collector_id)
            s2 = select([Gateway.gw_hex_id.label('id'),
                expression.literal_column('\'Gateway\'').label('type'),
                Gateway.name,
                DataCollector.name.label('data_collector'),
                Gateway.vendor]).\
                 where(Gateway.organization_id == 4).\
                 where(Gateway.data_collector_id == DataCollector.id)

            q = s1.union(s2)
            q = q.order_by(text('type desc'))
            q = q.alias('device_gateway')
            results = db.session.query(q).paginate(page=page, per_page=size)

            devices = [{
                'id' : dev.id,
                'type' : dev.type,
                'name' : dev.name,
                'data_collector' : dev.data_collector,
                'vendor' : dev.vendor,
                'application' : None,
                'tags' : []
            } for dev in results.items]
            headers = {'total-pages': results.pages, 'total-items': results.total}
            return {"devices": devices}, 200, headers
        except Exception as e:
            LOG.error(f"Error: {e}")
            return {"message" : str(e)}, 400