from iot_api import socketio

def emit_alert_event(event, recipient):
    socketio.emit('new_alert', event, room=recipient)