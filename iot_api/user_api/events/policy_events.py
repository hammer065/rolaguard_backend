import pika
import json
import iot_logging
from threading import Thread

from iot_api import rabbit_parameters

LOG = iot_logging.getLogger(__name__)


def emit_policy_event(type, data):
    
    def publish():
        event = {
            'type': type,
            'data': data
        }
        body = json.dumps(event)
        json.dumps(event)
        connection = pika.BlockingConnection(rabbit_parameters)
        channel = connection.channel()
        exchange = "policies_events"
        channel.exchange_declare(exchange=exchange, exchange_type='fanout')
        channel.basic_publish(exchange=exchange, routing_key='', body=body)
        connection.close()
        LOG.info(f"Published {type} event on {exchange}")

    thread = Thread(target = publish)
    thread.setDaemon(True)
    thread.start()
