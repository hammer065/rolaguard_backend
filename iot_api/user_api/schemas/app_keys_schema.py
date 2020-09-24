from marshmallow import Schema, fields
from marshmallow.validate import Length
from iot_api.user_api.repository.AppKeysRepository import MAX_PER_ORGANIZATION

class AppKeysSchema(Schema):
    keys = fields.List(fields.Str(), required=True, validate=Length(1, MAX_PER_ORGANIZATION))