from iot_api import socketio

def emit_notification_event(event, recipient):
    socketio.emit('new_notification', event, room=recipient)