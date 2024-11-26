# -*- coding: utf-8 -*-
from flask_sqlalchemy import SQLAlchemy
from iot_api import app

db = SQLAlchemy(app)
db.init_app(app)
