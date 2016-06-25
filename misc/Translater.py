from misc.Logger import logger
from misc import Misc


def translate_security_group_ip_address_in_cloudformation(cloudformation_json, env_cidr):
    for resource_name in cloudformation_json['Resources']:
        logger.debug(msg="Iterating over %s for sg translation" % (resource_name,))
        if 'Type' not in cloudformation_json['Resources'][resource_name] or 'AWS::EC2::SecurityGroup' != \
                cloudformation_json['Resources'][resource_name]['Type']:
            continue
        cloudformation_json['Resources'][resource_name] = translate_security_group(
            security_group=cloudformation_json['Resources'][resource_name], env_cidr=env_cidr)
    return cloudformation_json


def translate_security_group(security_group, env_cidr):
    ipranges = Misc.get_yaml(landscape_path="ipranges.yaml")
    ret = []
    for rule in security_group['Properties']['SecurityGroupIngress']:
        if 'CidrIp' in rule:
            logger.debug("We have a CidrIp in the security group")
            if rule['CidrIp'] == "vpc":
                ret.append(change_sg_cidr(rule=rule, iprange=env_cidr))
            elif rule['CidrIp'] == "self":
                print "self"
            elif rule['CidrIp'] in ipranges:
                for iprange in ipranges[rule['CidrIp']]:
                    ret.append(change_sg_cidr(rule=rule, iprange=iprange))
        else:
            ret.append(rule)
    security_group['Properties']['SecurityGroupIngress'] = ret
    logger.debug(msg="Translated security group: %s" % (ret,))
    return security_group


def change_sg_cidr(rule, iprange):
    temp_rule = dict(rule)
    temp_rule['CidrIp'] = iprange
    return temp_rule


def gather_information_for_cloudofrmation_parameters(stack_data, vpc, ami):
    parameters = []
    env = Misc.get_value_from_array_hash(dictlist=vpc.get('Tags'), key="Environment")
    if 'cloudformation_parameters' in stack_data:
        for parameter in stack_data['cloudformation_parameters']:
            if parameter["ParameterKey"] == "Environment":
                parameters.append({"ParameterKey": "Environment", "ParameterValue": env, "UsePreviousValue": False})
            elif parameter["ParameterKey"] == "InstanceType":
                instance = None
                if 'instance_type' in stack_data and env in stack_data['instance_type']:
                    instance = stack_data["instance_type"][env]
                else:
                    instance = Misc.get_value_from_array_hash(dictlist=ami.get('Tags'), key="Instancetype")
                parameters.append(
                    {"ParameterKey": "InstanceType", "ParameterValue": instance, "UsePreviousValue": False})
            elif parameter["ParameterKey"] == "Puppetrole":
                parameters.append({"ParameterKey": "Puppetrole", "ParameterValue": stack_data['puppet_role'],
                                   "UsePreviousValue": False})
            elif parameter["ParameterKey"] == "XivelyService":
                parameters.append({"ParameterKey": "XivelyService", "ParameterValue": stack_data['xively_service'],
                                   "UsePreviousValue": False})
            elif parameter["ParameterKey"] == "Ami":
                parameters.append(
                    {"ParameterKey": "Ami", "ParameterValue": stack_data['ami'], "UsePreviousValue": False})
            elif parameter["ParameterKey"] == "KeyName":
                key = Misc.get_value_from_array_hash(dictlist=vpc.get('Tags'), key="Keypair")
                parameters.append({"ParameterKey": "KeyName", "ParameterValue": key, "UsePreviousValue": False})
            else:
                parameter["UsePreviousValue"] = False
                parameters.append(parameter)
    else:
        logger.warning(msg="No cloudformation parameter object in json")
    logger.debug(msg="Cloudformation parameters is: %s" % (parameters,))
    return parameters
