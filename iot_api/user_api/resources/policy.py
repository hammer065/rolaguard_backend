from flask import jsonify, request
from flask_restful import Resource
from flask_jwt_extended import get_jwt_identity, jwt_required

import json
import iot_logging
from marshmallow import ValidationError

from iot_api.user_api.model import User, AlertType
from iot_api.user_api.models.Policy import Policy
from iot_api.user_api.models.DataCollector import DataCollector
from iot_api.user_api.models.PolicyItem import PolicyItem

from iot_api.user_api.schemas.policy_schema import PolicySchema, UpdatedPolicySchema

from iot_api.user_api.events.policy_events import emit_policy_event

from iot_api.user_api.Utils import is_admin_user, is_regular_user

LOG = iot_logging.getLogger(__name__)

class PolicyListResource(Resource):

    @jwt_required
    def get(self):

        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)
        organization_id = user.organization_id

        if not user or not organization_id or not is_admin_user(user.id) and not is_regular_user(user.id):
            return {}, 403

        page = request.args.get('page', default=1, type=int)
        size = request.args.get('size', default=20, type=int)

        result = Policy.find_with_collectors(organization_id, None, None, page, size)
        headers = {'total-pages': result.pages, 'total-items': result.total}
        policies = [policy.to_dict() for policy in result.items]

        return policies, 200, headers

    @jwt_required
    def post(self):

        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)
        organization_id = user.organization_id

        if not user or not organization_id or not is_admin_user(user.id):
            return {}, 403
        
        body = json.loads(request.data)
        parsed_result = None

        try:
            parsed_result = PolicySchema().load(body)
        except ValidationError as err:
            return err.messages, 400

        if len(parsed_result.errors.keys()) > 0:
            errors = []
            for key in parsed_result.errors.keys():

                errors.append(parsed_result.errors.get(key))
            return errors , 400

        # TODO Replace fetching the entity by something that issues an 'exists' query.
        if Policy.find(organization_id, parsed_result.data.get('name'), None).total > 0:
            return [{'code': 'EXISTING_NAME', 'message': 'Existing policy with that name'}], 400

        items = parsed_result.data.get('items')

        # This validation is disabled temporarily - https://trello.com/c/QFsIQ7Yw
        # Bring validation back as part of https://trello.com/c/0VnmKErd
        # alert_types = AlertType.find_all()
        # errors = validate_items(alert_types, items)
        # if len(errors) > 0:
        #     return errors, 400

        try:
            policy = Policy(
                name = parsed_result.data.get('name'),
                organization_id = organization_id,
                is_default = False
            )
            policy.save()

            for item in items:
                policy_item = PolicyItem(
                    alert_type_code = item.get('alert_type_code'),
                    policy_id = policy.id,
                    parameters = json.dumps(item.get('parameters')),
                    enabled = item.get('enabled')
                )
                policy_item.save()

            Policy.commit()

        except Exception as exc:
            Policy.rollback()
            LOG.error('Something went wrong trying to add the policy.{0}'.format(exc))
            return {'message': 'Something went wrong trying to add the policy.'}, 500

        res_body = policy.to_dict()
        emit_policy_event('CREATED', {'id': policy.id})

        return res_body, 201
        

class PolicyResource(Resource):

    @jwt_required
    def get(self, id):

        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)
        organization_id = user.organization_id

        if not user or not organization_id or not is_admin_user(user.id) and not is_regular_user(user.id):
            return [], 403

        policy = Policy.find_one(id, organization_id)
        if not policy:
            return None, 404
        
        if policy.organization_id is not None and policy.organization_id != organization_id:
            return [{'code': 'FORBIDDEN', 'message': 'Can\'t fetch the policy.'}], 403

        return policy.to_dict()

    @jwt_required
    def put(self, id):

        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)
        organization_id = user.organization_id
        if not user or not organization_id or not is_admin_user(user.id):
            return [], 403

        policy = Policy.find_one(id)        
        if not policy:
            return None, 404

        if policy.is_default:
            return [{'code': 'DEFAULT_POLICY', 'message': 'Can\'t update default policy.'}], 403
        
        if policy.organization_id != organization_id:
            return [{'code': 'FORBIDDEN', 'message': 'Can\'t delete the policy.'}], 403
        
        body = json.loads(request.data)
        parsed_result = None

        try:
            parsed_result = UpdatedPolicySchema().load(body)
        except ValidationError as err:
            return err.messages, 400

        if len(parsed_result.errors.keys()) > 0:
            return [parsed_result.errors], 400

        # TODO Replace fetching the entity by something that issues an 'exists' query.
        if Policy.find(organization_id, parsed_result.data.get('name'), id).total > 0:
            return [{'code': 'EXISTING_NAME', 'message': 'Existing policy with that name'}], 400

        items = parsed_result.data.get('items')

        # This validation is disabled temporarily - https://trello.com/c/QFsIQ7Yw
        # Bring validation back as part of https://trello.com/c/0VnmKErd
        # alert_types = AlertType.find_all()
        # errors = validate_items(alert_types, items)
        # if len(errors) > 0:
        #     return errors, 400

        try:
            policy.name = parsed_result.data.get('name')

            for item in items:
                policy_item = PolicyItem.find_one(item.get('id'))
                if policy_item.policy_id != id:
                    raise Exception('An item does not belong to this policy')
                policy_item.alert_type_code = item.get('alert_type_code'),
                policy_item.parameters = json.dumps(item.get('parameters')),
                policy_item.enabled = item.get('enabled')

            Policy.commit()

        except Exception as exc:
            Policy.rollback()
            LOG.error('Something went wrong trying to add the policy.{0}'.format(exc))
            return {'message': 'Something went wrong trying to add the policy.'}, 500

        res_body = policy.to_dict()
        emit_policy_event('UPDATED', {'id': id})
        return res_body, 200

    @jwt_required 
    def delete(self, id):

        user_identity = get_jwt_identity()
        user = User.find_by_username(user_identity)
        organization_id = user.organization_id

        if not user or not organization_id or not is_admin_user(user.id):
            return [], 403

        policy = Policy.find_one(id)
        if not policy:
            return None, 404

        if policy.is_default:
            return [{'code': 'DEFAULT_POLICY', 'message': 'Can\'t delete default policy.'}], 403
        
        if policy.organization_id != organization_id:
            return [{'code': 'FORBIDDEN', 'message': 'Can\'t delete the policy.'}], 403

        if DataCollector.count(organization_id, policy.id) > 0:
            return [{'code': 'POLICY_WITH_DATA_COLLECTORS', 'message': 'Can\'t delete policy with data collectors.'}], 403
        
        policy.delete()
        emit_policy_event('DELETED', {'id': id})
        return {}, 204


def validate_items(alert_types, items):
    
    """ Check if there's one and only one alert type for each item. For each alert type validate parameters.

    Parameters
    ----------
    alert_types : list, required
        description
    items : list, required
        description

    Returns
    -------
    dict
        a dictionary including information about error validations. If everything was ok, return an empty dictionary. """

    if len(alert_types) > len(items):
        return [{ 'code': 'MORE_TYPES_THAN_ITEMS', 'message': 'There\'re more alert types than items.' }]
    if len(alert_types) < len(items):
        return [{ 'code': 'LESS_TYPES_THAN_ITEMS', 'message': 'There\'re less alert types than items.' }]

    for type in alert_types:
        found_items = list(filter(lambda item: item.get('alert_type_code') == type.code, items))
        if len(found_items) > 1:
            return [{ 'code': 'MANY_ITEMS_FOR_TYPE', 'parameters': { 'count': len(found_items), 'type': type.code }, 'message': '{count} items for alert type {type}'.format(count = len(found_items), type = type.code) }]
        if len(found_items) < 1:
            return [{ 'code': 'NO_ITEM_FOR_TYPE', 'parameters': { 'type': type.code }, 'message': 'No items for alert type {type}'.format(type = type.code) }]

        errors = []

        for key in found_items[0].get('parameters').keys():
            value = found_items[0].get('parameters').get(key)
            parameter = json.loads(type.parameters).get(key, None)
            if not parameter:
                errors.append({ 'code': 'MISSING_PARAMETER', 'parameters': {'parameter': key, 'type': type.code}, 'message': 'Not existing parameter {param}'.format(param = key) })
            
            if value is not None:
                parameter_type = parameter.get('type', None)
                
                if parameter_type:
                    valid_type = True
                    if parameter_type == 'Integer' and not isinstance(value, int):
                        valid_type = False
                        errors.append({ 'code': 'NOT_VALID_TYPE', 'parameters': { 'parameter': key, 'type': type.code, 'requiredType': 'Integer'}, 'message': 'Not valid parameter {param}. Required type: Integer'.format(param = key) })
                    elif parameter_type == 'Float' and not isinstance(value, (int, float)):
                        valid_type = False
                        errors.append({ 'code': 'NOT_VALID_TYPE', 'parameters': { 'parameter': key, 'type': type.code, 'requiredType': 'Float'}, 'message': 'Not valid parameter {param}. Required type: Float'.format(param = key) })

                    max_value = parameter.get('maximum', None)
                    if valid_type and max_value is not None and value > max_value:
                        errors.append({ 'code': 'EXCEED_MAX_VALUE', 'parameters': {'type': type.code, 'parameter': key, 'maxValue': max_value}, 'message': 'Not valid parameter {param}. Max value is {max_value}. '.format(param = key, max_value = max_value)})
                    
                    min_value = parameter.get('minimum', None)
                    if valid_type and min_value is not None and value < min_value:
                        errors.append({ 'code': 'BELOW_MIN_VALUE', 'parameters': {'type': type.code, 'parameter': key, 'minValue': min_value}, 'message': 'Not valid parameter {param}. Min value is {min_value}. '.format(param = key, min_value = min_value)})
        
        return errors

    return []



