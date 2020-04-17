from flask import request
from flask_restful import Resource
from flask_jwt_extended import get_jwt_identity, jwt_required

import dateutil.parser as dateparser
from datetime import datetime
import json

from iot_api.user_api.model import User
from iot_api.user_api.models.notification import Notification
from iot_api.user_api.models.notification_type import NotificationType
from iot_api.user_api.models.notification_data import NotificationData

class NotificationListResource(Resource):

    @jwt_required
    def get(self):
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        if not user:
            return None, 403

        page = request.args.get('page', default=1, type=int)
        size = request.args.get('size', default=20, type=int)

        result = Notification.find(user.id, page, size)
        headers = {'total-pages': result.pages, 'total-items': result.total}
        notifications = [notification.to_dict() for notification in result.items]

        notification_data = NotificationData.find_one(user.id)
        if notification_data:
            notification_data.last_read = datetime.now()
            notification_data.update()
        else:
            NotificationData(user_id = user.id, last_read = datetime.now()).save()

        return notifications, 200, headers

class NotificationResource(Resource):

    @jwt_required
    def delete(self, id):
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        notification = Notification.find_one(id)
        if notification.user_id != user.id:
            return None, 403
        
        notification.delete()
        return None, 204

    @jwt_required
    def patch(self, id):
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        notification = Notification.find_one(id)
        if notification.user_id != user.id:
            return None, 403

        body = json.loads(request.data)
        read_at = None
        if body.get('readAt') is not None:
            try:
                read_at = dateparser.parse(body.get('readAt'))
            except Exception:
                return {'error': 'Bad value for readAt field'}, 400
        
        notification.read_at = read_at
        Notification.commit()
        return notification.to_dict(), 200
        

class NotificationCountResource(Resource):

    @jwt_required
    def get(self):
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)

        notification_data = NotificationData.find_one(user.id)
        if notification_data:
            _from = notification_data.last_read
        else:
            _from = None

        count = Notification.count(user.id, _from)
        return {'count': count}
