from marshmallow import Schema, fields

class PolicyItemSchema(Schema):
    alertTypeCode = fields.Str(required=True, attribute='alert_type_code', error_messages={'required': {'code': 'MISSING_ALERT_TYPE_CODE', 'message': 'Missing alert type code'}})
    enabled = fields.Bool(required=True, error_messages={'required': {'code': 'MISSING_ENABLED', 'message': 'Missing enabled'}})
    parameters = fields.Dict(required=True, error_messages={'required': {'code': 'MISSING_PARAMETERS', 'message': 'Missing parameters'}})

class UpdatedPolicyItemSchema(Schema):
    id = fields.Int(required=True, error_messages={'required': {'code': 'MISSING_ID', 'message': 'Missing id'}})
    alertTypeCode = fields.Str(required=True, attribute='alert_type_code', error_messages={'required': {'code': 'MISSING_ALERT_TYPE_CODE', 'message': 'Missing alert type code'}})
    enabled = fields.Bool(required=True, error_messages={'required': {'code': 'MISSING_ENABLED', 'message': 'Missing enabled'}})
    parameters = fields.Dict(required=True, error_messages={'required': {'code': 'MISSING_PARAMETERS', 'message': 'Missing parameters'}})