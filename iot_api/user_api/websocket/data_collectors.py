from iot_api import socketio

def emit_data_collector_event(event_type, event, recipient):
    socketio.emit(event_type, event, room=recipient)
