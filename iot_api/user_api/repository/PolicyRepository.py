import iot_logging, json
LOG = iot_logging.getLogger(__name__)

from sqlalchemy import not_

from iot_api.user_api import db
from iot_api.user_api.model import AlertType
from iot_api.user_api.models.PolicyItem import PolicyItem

def add_missing_items(policy_id, existing_type_codes):
    """
    For every alert type whose code is not present in 'existing_type_codes'
    add a policy item for this alert type and this policy with default values.
    Returns true if at least one item was added
    """
    missing_alert_types = db.session.query(AlertType).filter(not_(AlertType.code.in_(existing_type_codes))).all()
    if not missing_alert_types:
        return False
    
    for alert_type in missing_alert_types:
        parameters = json.loads(alert_type.parameters)
        parameters = {par : val['default'] for par, val in parameters.items()}
        db.session.add(PolicyItem(
            policy_id=policy_id,
            alert_type_code=alert_type.code,
            enabled=True,
            parameters=json.dumps(parameters)))
            
    db.session.commit()
    return True