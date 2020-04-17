from flask_restful import Resource
from flask_jwt_extended import get_jwt_identity, jwt_required

from datetime import datetime, timedelta

from iot_api.user_api.model import Packet, User

from iot_api.user_api.endpoints import is_admin_user, is_regular_user

class DataCollectorActivityResource(Resource):
    
    @jwt_required
    def get(self):
        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)
        organization_id = user.organization_id

        if not user or not organization_id or not is_admin_user(user.id) and not is_regular_user(user.id):
            return None, 403
        
        min_date = datetime.today() - timedelta(hours=4)
        result = Packet.find_max_by_organization_id(organization_id, min_date)
        response = list(map(lambda item: {'dataCollectorId': item.data_collector_id, 'maxDate': "{}".format(item.date)}, result))
        return response, 200
