import os, sys
from iot_logging import getLogger
log = getLogger(__name__)

# Pagination
MAX_PER_PAGE = 1000
ERROR_OUT = False

try:
    BRAND_NAME = os.environ['BRAND_NAME']
except:
    BRAND_NAME = "RoLaGuard CE"
try:
    BRAND_URL = os.environ['BRAND_URL']
except:
    BRAND_URL = "localhost:30000"
log.info(f'Using "{BRAND_NAME}" as brand and {BRAND_URL} as URL')

# Features
try:
    SEND_EMAILS = True if os.environ['SEND_EMAILS'] == "True" else False
except:
    SEND_EMAILS = False

try:
    ASSIGN_COLLECTOR_TO_USER_ENABLED = True if os.environ['ASSIGN_COLLECTOR_TO_USER_ENABLED'] == "True" else False
except:
    ASSIGN_COLLECTOR_TO_USER_ENABLED = False

try:
    SEND_SMS = True if os.environ['SEND_SMS'] == "True" else False
except:
    SEND_SMS = False

# SMTP service
if SEND_EMAILS:
    try:
        SMTP_HOST = os.environ['SMTP_HOST']
        SMTP_PORT = int(os.environ['SMTP_PORT'])
        SMTP_USERNAME = os.environ['SMTP_USERNAME']
        SMTP_PASSWORD = os.environ['SMTP_PASSWORD']
        SMTP_SENDER = os.environ['SMTP_SENDER']
        SMTP_SENDER_NAME = os.environ['SMTP_SENDER_NAME']
        SMTP_MAX_SEND_MAIL_ATTEMPTS = int(os.environ['SMTP_MAX_SEND_MAIL_ATTEMPTS'])
    except Exception as e:
        log.error("SMTP enviroment variables not found: {0}".format(e))
        sys.exit(1)

# Database
try:
    DB_NAME = os.environ['DB_NAME']
    DB_USERNAME = os.environ['DB_USERNAME']
    DB_PASSWORD = os.environ['DB_PASSWORD']
    DB_HOST = os.environ['DB_HOST']
    DB_PORT =  int(os.environ['DB_PORT'])
except Exception as e:
    log.error("DB enviroment variables not found: {0}".format(e))
    sys.exit(1)

SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user=DB_USERNAME, pw=DB_PASSWORD, url=DB_HOST, db=DB_NAME)

# Messaging Broker
try:
    FLASK_PIKA_PARAMS = {
        'host': os.environ['RABBITMQ_HOST'],
        'username': os.environ['RABBITMQ_DEFAULT_USER'],
        'password': os.environ['RABBITMQ_DEFAULT_PASS'],
        'port': int(os.environ['RABBITMQ_PORT'])
    }
    FLASK_PIKA_POOL_PARAMS = {
        'pool_size': int(os.environ['RABBITMQ_POOL_SIZE']),
        'pool_recycle': int(os.environ['RABBITMQ_POOL_RECYCLE'])
    }
except Exception as e:
    log.error("PIKA enviroment variables not found: {0}".format(e))
    sys.exit(1)

PROPAGATE_EXCEPTIONS = True

# Global date format
DATE_FORMAT = "%Y-%m-%d %H:%M:%S%z"