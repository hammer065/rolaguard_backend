import json
import logging as log
from sqlalchemy.sql import select, expression, text
from flask import request, abort, jsonify
from flask_restful import reqparse
from flask_jwt_extended import get_jwt_identity

from iot_api.user_api import db
from iot_api.user_api.models import User
from iot_api.user_api.Utils import is_admin_user, is_regular_user
from iot_api.user_api.model import Device, Gateway


parser = reqparse.RequestParser()
parser.add_argument("data_collector", required=False)
parser.add_argument("gateway_id", required=False)

class DeviceInventoryAPI(Resource):
    @jwt_required
    def get(self):
        log.info("inventory")
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)
        if not user or not is_admin_user(user.id) and not is_regular_user(user.id):
            return abort(403, error='forbidden access')

        organization_id = user.organization_id
        page = request.args.get('page')
        size = request.args.get('size')

        if page:
            try:
                page = int(page)
            except Exception:
                abort(400, error='no valid page value')

        if size:
            try:
                size = int(size)
            except Exception:
                return abort(400, error='no valid size value')

        s1 = select([Device.dev_eui.label('id'),
             expression.literal_column('\'Device\'').label('type'),
             Device.name,
             Device.vendor]).where(Device.organization_id == 4)
        s2 = select([Gateway.gw_hex_id.label('id'),
                    expression.literal_column('\'Gateway\'').label('type'),
                    Gateway.name,
                    Gateway.vendor]).where(Gateway.organization_id == 4)
        q = s1.union(s2)
        q = q.order_by(text('type desc'))
        q = q.alias('device_gateway')
        results = db.session.query(q).paginate(page=page, per_page=size)

        devices = [jsonify({
                'id' : dev.id,
                'type' : dev.type,
                'name' : dev.name,
                'vendor' : dev.vendor
            }) for dev in results.items]
        headers = {'total-pages': results.pages, 'total-items': results.total}

        return {"devices": devices}, 200, headers