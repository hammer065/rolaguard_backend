from marshmallow import fields, Schema

class AssetSchema(Schema):
	asset_id = fields.Integer(required=True)
	asset_type = fields.String(required=True)

class AssetHidingSchema(Schema):
	hidden = fields.Bool(required=True)
	asset_list = fields.Nested(AssetSchema, many=True, required=False)