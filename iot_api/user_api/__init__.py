# -*- coding: utf-8 -*-
from flask_sqlalchemy import SQLAlchemy
from iot_api import app
from flask_sqlalchemy import event

db = SQLAlchemy(app)
db.init_app(app)

def my_on_checkout(dbapi_conn, connection_rec, connection_proxy):
    "handle an on checkout event"
#    print('check out event')
#    print(dbapi_conn)
#    print(connection_rec)
#    print(connection_proxy)

def receive_checkin(dbapi_connection, connection_record):
#    print('check in event')
#    print(dbapi_connection)
#    print(connection_record)
    "listen for the 'checkin' event"

def receive_close(dbapi_connection, connection_record):
#    print('close event')
#    print(dbapi_connection)
#    print(connection_record)
    "listen for the 'close' event"

def receive_connect(dbapi_connection, connection_record):
    # print('connect event')
#    print(dbapi_connection)
#    print(connection_record)
    "listen for the 'connect' event"

event.listen(db.engine, 'checkout', my_on_checkout)
event.listen(db.engine, 'checkin', receive_checkin)
event.listen(db.engine, 'close', receive_close)
event.listen(db.engine, 'connect', receive_connect)


