import traceback
from iot_api import app
from iot_api.user_api import db
import werkzeug
import marshmallow

import iot_logging
log = iot_logging.getLogger(__name__)

# Definition of exception types. In the future more types can be defined.
class BadRequest(Exception):
    html_code = 400
    error_msg = "Bad request"
    
class Unauthorized(Exception):
    html_code = 401
    error_msg = "Unauthorized"

class Forbidden(Exception):
    html_code = 403
    error_msg = "Forbidden"

class NotFound(Exception):
    html_code = 404
    error_msg = "Not found"

class UnprocessableEntity(Exception):
    html_code = 422
    error_msg = "Unprocessable entity"

# Error handlers: these functions are called when an exception is raised.
# In most cases they respond with a short message and the corresponding
# HTML error code.
@app.errorhandler(BadRequest)
def handle_400(error):
    log.error(str(error))
    return {"message" : error.error_msg}, error.html_code

@app.errorhandler(Unauthorized)
def handle_401(error):
    log.error(str(error))
    return {"message" : error.error_msg}, error.html_code

@app.errorhandler(Forbidden)
def handle_403(error):
    log.error(str(error))
    return {"message" : error.error_msg}, error.html_code

@app.errorhandler(NotFound)
def handle_404(error):
    log.error(str(error))
    return {"message" : error.error_msg}, error.html_code

@app.errorhandler(UnprocessableEntity)
def handle_422(error):
    log.error(str(error))
    return {"message" : error.error_msg}, error.html_code

# In this handler we catch all the exceptions that not were handled by the other
# handler, i.e the exceptions raised by Flask and the internal errors.
@app.errorhandler(Exception)
def handle_error(error):
    # Just in case, a rollback is triggered in the database for any error
    db.session.rollback()
    # Re-route the error according to its type
    if isinstance(error, werkzeug.exceptions.BadRequest):
        return handle_400(BadRequest(error))
    elif isinstance(error, werkzeug.exceptions.Unauthorized):
        return handle_401(Unauthorized(error))
    elif isinstance(error, werkzeug.exceptions.Forbidden):
        return handle_403(Forbidden(error))
    elif isinstance(error, werkzeug.exceptions.NotFound):
        return handle_404(NotFound(error))
    elif isinstance(error, werkzeug.exceptions.UnprocessableEntity):
        return handle_422(UnprocessableEntity(error))
    elif isinstance(error, marshmallow.ValidationError):
        return handle_400(BadRequest(error))
    else:
        # For not typified exceptions, the server respond with a html code 500 
        # and save the message and traceback in the log.
        log.error(f"{str(error)}\n {traceback.format_exc()}")
        return {"message" : "Internal error"}, 500
