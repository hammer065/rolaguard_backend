import pika
import json
import iot_logging
from threading import Thread
from datetime import datetime
from iot_api import rabbit_parameters
from iot_api.user_api.models import GlobalData
from iot_api.user_api.models.DataCollector import DataCollector, DataCollectorStatus
from iot_api.user_api.models.DataCollectorLogEvent import DataCollectorLogEvent, DataCollectorLogEventType

from iot_api.user_api.websocket.data_collectors import emit_data_collector_event as emit_data_collector_event_ws

# WebSocket channels
TESTED_DATA_COLLECTOR = 'tested_data_collector'
UPDATED_DATA_COLLECTOR = 'updated_data_collector'

LOG = iot_logging.getLogger(__name__)

def subscribe_data_collector_consumers():
    # status events
    thread = Thread(target = consumer)
    thread.setDaemon(True)
    thread.start()
    # test events
    thread_test = Thread(target = test_results_consumer)
    thread_test.setDaemon(True)
    thread_test.start()


# region test events
def test_results_consumer():
    exchange = 'data_collectors_events'
    queue = 'data_collectors_test_events'
    while(True):
        try:
            LOG.debug(f'Creating new connection to queue {queue}')
            connection = pika.BlockingConnection(rabbit_parameters)
            channel = connection.channel()
            channel.exchange_declare(exchange=exchange, exchange_type='direct')
            channel.queue_declare(queue=queue)
            channel.basic_consume(on_message_callback=handle_test_events, queue=queue, auto_ack=True)
            channel.start_consuming()
        except Exception as e:
            LOG.error(f"Error connecting to queue {queue}. Retrying connection.")

def handle_test_events(ch, method, properties, body):
    """
    Handle TEST results from Orchestrator
    expected format:
    {
        'data_collector_id': collector_id,
        'type': 'SUCCESS'/'ERROR',
        'message': 'error description'
    }
    """
    LOG.debug("New event on queue data_collectors_test_events received")
    event = None
    try:
        event = json.loads(body)
        LOG.debug(f"New event received: {event}")
    except Exception:
        LOG.warn('Couldn\'t deserialize event')

    if not event:
        return

    key = 'TestResponse-'+event['data_collector_id']
    result = GlobalData(key=key, value=json.dumps(event))
    try:
        result.save_to_db()
    except Exception:
        result.rollback()
        LOG.error("Couldn\'t save the event, making a rollback")
    else:
        LOG.debug("Event saved to db")
    # emit_data_collector_event_ws(TESTED_DATA_COLLECTOR, event, event.get('data_collector_id'))
# endregion

# region status events
def consumer():
    while(True):
        try:
            queue = 'data_collectors_status_events'
            exchange = 'data_collector_events'

            LOG.debug(f'Creating new connection to queue {queue}')
            connection = pika.BlockingConnection(rabbit_parameters)
            channel = connection.channel()
            channel.exchange_declare(exchange=exchange, exchange_type='direct')
            channel.queue_declare(queue=queue)
            channel.basic_consume(on_message_callback=handle_status_events, queue=queue, auto_ack=True)
            channel.start_consuming()
        except Exception as e:
            LOG.error(f"Error on connection to queue {queue}. Retrying connection.")
            continue

def handle_status_events(ch, method, properties, body):
    LOG.debug('New event on data_collector_status_events queue: {body}'.format(body=body))
    # LOG.info('Raising exception!')
    # raise Exception('Error provocado por nosotros!')

    event = None
    try:
        event = json.loads(body)        
    except Exception:
        LOG.warn('Couldn\'t deserialize event')

    if not event:
        return 

    data_collector_id = event.get('data_collector_id')
    new_status = event.get('status')
    data_collector = DataCollector.find_by_id(data_collector_id)
    new_verified = event.get('verified', data_collector.verified) #by default consider the actual value

    if not data_collector:
        return

    if event.get('type', None) == 'FAILED_PARSING':
        # Create log event
        try:
            parameters = { 'message': event.get('message', None) }
            log_event = DataCollectorLogEvent(
                data_collector_id = data_collector_id,
                created_at = datetime.now(),
                parameters = json.dumps(parameters),
                type = DataCollectorLogEventType.FAILED_PARSING
            )
            log_event.save()
        except Exception as exc:
            LOG.warn('There was an error generating log event: {error}'.format(error=exc))
    
    elif event.get('type', None) == 'FAILED_LOGIN':
        try:
            parameters = {}
            log_event = DataCollectorLogEvent(
                data_collector_id = data_collector_id,
                created_at = datetime.now(),
                parameters = json.dumps(parameters),
                type = DataCollectorLogEventType.FAILED_LOGIN
            )
            log_event.save()
        except Exception as exc:
            LOG.warn('There was an error generating log event: {error}'.format(error=exc))
        
    if not new_status:
        return
    
    if new_status == 'DISCONNECTED' and data_collector.status == DataCollectorStatus.CONNECTED:
        new_status = DataCollectorStatus.DISCONNECTED

        # Create log event
        try:
            if event.get('is_restart', None):

                parameters = { }
                log_event = DataCollectorLogEvent(
                    data_collector_id = data_collector_id,
                    created_at = datetime.now(),
                    parameters = json.dumps(parameters),
                    type = DataCollectorLogEventType.RESTARTED
                )
                log_event.save()

            parameters = { 'error': event.get('error', None) }
            log_event = DataCollectorLogEvent(
                data_collector_id = data_collector_id,
                created_at = datetime.now(),
                parameters = json.dumps(parameters),
                type = DataCollectorLogEventType.DISCONNECTED
            )
            log_event.save()
        except Exception as exc:
            LOG.warn('There was an error generating log event: {error}'.format(error=exc))

    elif new_status == 'CONNECTED' and data_collector.status == DataCollectorStatus.DISCONNECTED:
        new_status = DataCollectorStatus.CONNECTED
        # Create log event
        try:
            parameters = {}
            log_event = DataCollectorLogEvent(
                data_collector_id = data_collector_id,
                created_at = datetime.now(),
                parameters = json.dumps(parameters),
                type = DataCollectorLogEventType.CONNECTED
            )
            log_event.save()
        except Exception as exc:
            LOG.warn('There was an error generating log event: {error}'.format(error=exc))

    elif new_verified == data_collector.verified:
        return
        
    try:
        data_collector.status = new_status
        if new_verified != data_collector.verified:
            data_collector.verified = new_verified
        try:
            data_collector.update_to_db()
        except Exception as exc:
            data_collector.rollback()
            raise exc
    except Exception:
        LOG.error('Couldn\'t update data collector status')

    emit_data_collector_event_ws(UPDATED_DATA_COLLECTOR, data_collector.to_json(), data_collector.organization_id)
#endregion


def emit_data_collector_event(type, data):
    event = {
        'type': type,
        'data': data
    }
    body = json.dumps(event)
    queue = 'data_collectors_events'

    connection = pika.BlockingConnection(rabbit_parameters)
    channel = connection.channel()
    channel.queue_declare(queue=queue)
    channel.basic_publish(exchange='', routing_key=queue, body=body)
    LOG.debug('Published {type} event on {queue}'.format(type=type, queue=queue))
    # emit_data_collector_event_ws(UPDATED_DATA_COLLECTOR, data, data.get('organization_id'))

subscribe_data_collector_consumers()
