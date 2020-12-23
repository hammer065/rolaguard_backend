# -*- coding: utf-8 -*-
import iot_logging

import eventlet
eventlet.monkey_patch()

from flask import Flask
from flask_restful import Api
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from iot_api import config
from cryptography.fernet import Fernet
from flask_session import Session
import pika
import os, sys
from flask_socketio import SocketIO
from iot_logging import getLogger
log = getLogger(__name__)

iot_logging.getLogger(__name__)
app = Flask(__name__, static_url_path="", instance_relative_config=True)

CORS(app, expose_headers=['total-items', 'total-pages'])
app.config.from_object(config)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True

app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

try:
    app.config['SECRET'] = os.environ['SECRET']
    app.config['JWT_SECRET_KEY'] = os.environ['JWT_SECRET_KEY']
    key= os.environ['MASTER_KEY']
except Exception as e:
    log.error("SECRETs enviroment variables not found: {0}".format(e))
    sys.exit(1)

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_pre_ping': True, 'echo_pool': True}



api = Api(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
cipher_suite = Fernet(key)
mail = Mail(app)

rabbit_credentials = pika.PlainCredentials(
    config.FLASK_PIKA_PARAMS['username'],
    config.FLASK_PIKA_PARAMS['password'])

rabbit_parameters = pika.ConnectionParameters(
    host=config.FLASK_PIKA_PARAMS['host'],
    port=config.FLASK_PIKA_PARAMS['port'],
    credentials=rabbit_credentials,
    heartbeat=30
    )

socketio = SocketIO(
    app,
    message_queue='amqp://{user}:{password}@{host}:{port}'.format(
        user=config.FLASK_PIKA_PARAMS.get('username'),
        password=config.FLASK_PIKA_PARAMS.get('password'),
        host=config.FLASK_PIKA_PARAMS.get('host'),
        port=config.FLASK_PIKA_PARAMS.get('port')),
    cors_allowed_origins="*")