from marshmallow import Schema, fields, validates, ValidationError
from iot_api.user_api.schemas.policy_item_schema import PolicyItemSchema, UpdatedPolicyItemSchema

class PolicySchema(Schema):
    name = fields.Str(required=True, error_messages={'required': {'code': 'MISSING_NAME', 'message': 'Missing name'}})
    items = fields.Nested(PolicyItemSchema, many=True, required=True, error_messages={'required': {'code': 'MISSING_ITEMS', 'message': 'Missing items'}})

    @validates('name')
    def validate_name(self, value):
        if len(value) < 3:
            raise ValidationError({'code': 'BELOW_MIN_LENGTH', 'parameters': {'minLength': 2}, 'message': 'Name length must be greater than 2.'})
        if len(value) > 100:
            raise ValidationError({'code': 'EXCEED_MAX_LENGTH', 'parameters': {'maxLength': 100}, 'message': 'Name length can\'t greater than 100.'})


class UpdatedPolicySchema(Schema):
    name = fields.Str(required=True)
    items = fields.Nested(UpdatedPolicyItemSchema, many=True, required=True)

    @validates('name')
    def validate_name(self, value):
        if len(value) < 3:
            raise ValidationError({'code': 'BELOW_MIN_LENGTH', 'parameters': {'minLength': 2}, 'message': 'Name length must be greater than 2.'})
        if len(value) > 100:
            raise ValidationError({'code': 'EXCEED_MAX_LENGTH', 'parameters': {'maxLength': 100}, 'message': 'Name length can\'t greater than 100.'})
