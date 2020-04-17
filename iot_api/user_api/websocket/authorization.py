from flask import request
from flask_socketio import emit, send, join_room, leave_room
from flask_jwt_extended import decode_token

from iot_api import socketio

from iot_api.user_api.model import User
from iot_api.user_api.models.notification_data import NotificationData


@socketio.on('authorization')
def handle_authorization(message):
    token = message.get('token')
    decoded_token = decode_token(token, allow_expired = True)
    identity = decoded_token.get('identity')
    user = User.find_by_username(identity)
    organization = user.organization_id
    join_room(organization)
    data = NotificationData.find_one(user.id)
    if data:
        data.ws_sid = request.sid
        data.update()
    

#@socketio.on('connect')
#def test_connect():
    #print('connected')

@socketio.on('disconnect')
def disconnect():
    data = NotificationData.find_one_by_sid(request.sid)
    if data:
        data.ws_sid = None
        data.update()