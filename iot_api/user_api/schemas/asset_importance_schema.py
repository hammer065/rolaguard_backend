from marshmallow import fields, Schema

class AssetSchema(Schema):
    asset_id = fields.Integer(required=True)
    asset_type =  fields.String(required=True)

class AssetImportanceSchema(Schema):
    importance = fields.String(required=True)
    asset_list = fields.Nested(AssetSchema, many=True, required=True)
