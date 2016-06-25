import sys
from random import randint
import os
import string
import random
from misc.Logger import logger
import concurrent.futures
import json

ec2_columns = {'id': 'InstanceId', 'ebs_optimized': 'EbsOptimized', 'root_device_type': 'RootDeviceType',
               'root_device_name': 'RootDeviceName', 'platform': 'Platform', 'public_ip_address': 'PublicIpAddress',
               'private_ip_address': 'PrivateIpAddress', 'vpc_id': 'VpcId', 'image_id': 'ImageId',
               'launch_time': 'LaunchTime', 'instance_type': 'InstanceType', 'private_dns_name': 'PrivateDnsName',
               'public_dns_name': 'PublicDnsName', 'tag:name': 'Name', 'tag:xively_service': 'Xively_service',
               'tag:puppet_role': 'Puppet_role', 'tag:owner': 'Owner', 'tag:env': 'Environment',
               'monitoring_state': 'Monitoring.State', 'placement': 'Placement.AvailabilityZone', 'state': 'State.Name'}

elb_columns = {'name': 'LoadBalancerName', 'facing': 'Scheme', 'tag:xively_service': 'Xively_service',
               'tag:puppet_role': 'Puppet_role', 'tag:env': 'Env', 'dns_name': 'DNSName', 'vpcid': 'VPCId',
               'createtime': 'CreatedTime', 'availabilityzone': 'AvailabilityZones', 'securitygroups': 'SecurityGroups',
               'instances': 'Instances', 'instance_num': 'Instances', 'listener': 'ListenerDescription'}

cloudformation_columns = {'name': 'StackName', 'id': 'StackId', 'description': 'Description',
                          'createtime': 'CreationTime', 'lastupdatetime': 'LastUpdateTime', 'status': 'StackStatus',
                          'timeout': 'TimeoutInMinutes'}

kinesis_columns = {'name': 'StreamName', 'arn': 'StreamARN', 'status': 'StreamStatus',
                   'retentionhours': 'RetentionPeriodHours'}

ami_columns = {'id': 'ImageId', 'location': 'ImageLocation', 'state': 'State', 'creation': 'CreationDate',
               'public': 'Public', 'platform': 'Platform', 'sriov': 'SriovNetSupport', 'name': 'Name',
               'description': 'Description', 'rootdevice': 'RootDeviceType', 'virtualizationtype': 'VirtualizationType',
               'tag:puppet_role': 'Puppet_role', 'tag:availability': 'Availability', 'tag:instancetype': 'Instancetype',
               'tag:os': 'Os'}

vpc_columns = {'id': 'VpcId', 'state': 'State', 'cidr': 'CidrBlock', 'tenancy': 'InstanceTenacy',
               'default': 'IsDefault', 'tag:environment': 'Environment', 'tag:domain': 'Domain',
               'tag:keypair': 'Keypair', 'tag:availability': 'Availability', 'tag:name': 'Name'}

autoscale_columns = {}

iam_columns = {}

rds_columns = {}

sg_columns = {}

s3_columns = {}

route53_columns = {}

apigateway_columns = {'id': 'id', 'name': 'name', 'description': 'description', 'createdate': 'createdDate'}
"""
This variable is used to define the dynamo table for kerrigan. It should be same in all envs
"""
landscape_dynamo_table_name = "kerrigan"

try:
    import yaml
except ImportError:
    logger.error("Could not import yaml, decide what to do later")


def cli_argument_parse():
    # FIXME test this, need to mock sysargv somehow
    '''
    This function parses and removes cli arguments that the argparse should not handle
    :return: an array with logger option and aws account options
    :rtype: array
    '''
    logger.info("Parsing CLI arguments for global options")
    ret_logger = {'table': True, 'csv': False}
    ret = {}
    i = 0
    while i < len(sys.argv):
        if i >= len(sys.argv):
            break
        if sys.argv[i] == '--aws_access_key':
            ret['aws_access_key_id'] = sys.argv[i + 1]
            sys.argv.pop(i + 1)
            sys.argv.pop(i)
            i -= 1
        elif sys.argv[i] == '--aws_secret_key':
            ret['aws_secret_access_key'] = sys.argv[i + 1]
            sys.argv.pop(i + 1)
            sys.argv.pop(i)
            i -= 1
        elif sys.argv[i] == '--aws_region':
            ret['region_name'] = sys.argv[i + 1]
            sys.argv.pop(i + 1)
            sys.argv.pop(i)
            i -= 1
        elif sys.argv[i] == '--aws_account':
            ret['profile_name'] = sys.argv[i + 1]
            sys.argv.pop(i + 1)
            sys.argv.pop(i)
            i -= 1
        if sys.argv[i] == '--table':
            logger.info("Table output is being used")
            ret_logger['table'] = True
            ret_logger['csv'] = False
            sys.argv.pop(i)
            i -= 1
        elif sys.argv[i] == '--csv':
            logger.info("Csv output is being used")
            ret_logger['table'] = False
            ret_logger['csv'] = True
            sys.argv.pop(i)
            i -= 1
        else:
            i += 1
    logger.debug("Cli opts parsed: %s" % (ret,))
    return [ret, ret_logger]


def random3digit():
    '''
    This function returns a 3 digit random number
    :return: A 3 digit random number
    :rtype: int
    '''
    return str("%0.3d" % randint(1, 999))


def parse_object(service, columns, object):
    # FIXME test and document
    logger.debug("Object is: %s" % (object,))
    model = {}
    columns_hash = get_supported_columns(service=service)
    for column in columns:
        key = columns_hash[column]
        value = object.get(key)
        if column.startswith('tag:'):
            if 'Tags' in object:
                model[key] = get_value_from_array_hash(dictlist=object['Tags'], key=key)
            else:
                model[key] = None
        elif "." in key:
            [first_key, second_key] = key.split(".")
            model[key] = object.get(first_key).get(second_key)
        else:
            model[key] = value
    logger.debug("Model is: %s" % (model,))
    return model


def format_boto3_filter(filters):
    '''
    This function is used to format command line string argument to boto3 filter
    :param filters: A string in following format key1:value1,key2:value2
    :type filters: string
    :return: A array containing hashes of filter objects
    :rtype: dict
    '''
    ret = []
    array = string_to_array(string=filters, split_char=",")
    for statement in array:
        [name, value] = statement.split(':')
        ret.append({'Name': name, 'Values': [value]})
    return ret


def merge_dicts(dict1, dict2, path=None):
    '''
    This function merges two dicts, and returns a unified dict
    :param dict1: The first dict
    :type dict1: dict
    :param dict2: The second dict
    :type dict2: dict
    :param path: Under which path should we merge
    :return: A unified dict
    :rtype: dict
    '''
    if path is None: path = []
    for key in dict2:
        if key in dict1:
            if isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
                merge_dicts(dict1[key], dict2[key], path + [str(key)])
            elif dict1[key] == dict2[key]:
                pass  # same leaf value
            else:
                raise Exception('Conflict at %s' % '.'.join(path + [str(key)]))
        else:
            dict1[key] = dict2[key]
    return dict1


def get_value_from_array_hash(dictlist=None, key=None):
    '''
    This function returns the Value from the Tags hash with the requested key
    :param dictlist: The objects Tags array
    :type dictlist: list[dict]
    :param key: The requested key
    :type key: string
    :return: The value of the requested key, None is returned if key not present
    :rtype: string
    '''
    try:
        ret = filter(lambda x: x['Key'] == key, dictlist)[0]['Value']
    except IndexError:
        ret = None
    return ret


def parallel_map_reduce(map_func, reduce_func, iterable, output_init):
    # FIXME document or test
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = map(lambda x: executor.submit(map_func, x), iterable)
    result = reduce(lambda aggregate, item: reduce_func(aggregate, item.result()),
                    concurrent.futures.as_completed(futures), output_init)
    return result


def list_to_multiline_string(list=None):
    '''
    This function converts a list to a multiline string
    :param list: The list to convert
    :type list: array/list
    :return: a multiline string
    :rtype: string
    '''
    ret = ""
    if list is not None or list != "":
        ret = '\n'.join([str(x) for x in list])
    return ret


def join_list_to_string(join_with=',', list=None):
    '''
    This function converts a list to a string
    :param join_with: The character used to merge
    :type join_with: 1 delimiter char
    :param list: a list to join together
    :type list: array/list
    :return: A string
    '''
    ret = ""
    if list is not None or list != "":
        ret = join_with.join(list)
    return ret


def string_to_array(string=None, split_char='.'):
    '''
    This functions splits up a string along a delimiter to an array
    :param string: The string that needs to be splitted
    :type string: string
    :param split_char: the special account that should be the delimiter
    :type split_char: char
    :return: an array with the splitted characters
    :rtype: array
    '''
    return string.split(split_char)


def remove_last_n_char(string=None, char_num=1):
    '''
    This function removes n characters from the end of the string and returns the remaining
    :param string: the string to manipulate
    :type string: basestring
    :param char_num: the number of characters to remove
    :type char_num: int
    :return: the string without n chars
    :rtype: basestring
    '''
    if isinstance(char_num, int):
        ret = string[:-char_num]
    else:
        ret = string
    return ret


def merge_flatten_dict(dictionary, key):
    '''
    This function moves a sub hash one step hiher with prefix like key_subhashkey
    :param dictionary: the top level dict
    :type dictionary: dict
    :param key: the key to move higher
    :type key: string
    :return: a flattened dict
    :rtype: dict
    '''
    if key in dictionary and isinstance(dictionary[key], dict):
        for k, v in dictionary[key].items():
            del (dictionary[key][k])
            dictionary[key + "_" + k] = v
        del (dictionary[key])
    return dictionary


def str2bool(v):
    '''
    This function converts a string to boolean
    :param v: a string containing any form of true or false
    :type v: string
    :return: A true or false
    :rtype: boolean
    '''
    if v is None or v == "":
        return False
    return v.lower() in ("yes", "true", "t", "1")


def str2none(v):
    ret = v
    if v is None or v.lower() == "none":
        ret = None
    return ret

def parse_arn(arn):
    '''
    This function parses an arn and returns a dict with items seperated
    :param arn: A aws arn
    :type arn: string
    :return: A dict with the arn splitted
    :rtype: dict
    '''
    splitted_arn = arn.split(':')
    if len(splitted_arn) < 6:
        logger.error("Invalid arn: %s" % arn, )
        return None
    ret = {'arn': splitted_arn[0], 'partition': splitted_arn[1], 'service': splitted_arn[2], 'region': splitted_arn[3],
           'account-id': splitted_arn[4], 'resource': splitted_arn[5]}
    if len(splitted_arn) > 6:
        ret['resource_sub'] = splitted_arn[6]
    return ret


def confirm(prompt=None, resp=False):
    # FIXME find a way to test this
    """prompts for yes or no response from the user. Returns True for yes and
    False for no.

    'resp' should be set to the default value assumed by the caller when
    user simply types ENTER.

    >>> confirm(prompt='Create Directory?', resp=True)
    Create Directory? [y]|n:
    True
    >>> confirm(prompt='Create Directory?', resp=False)
    Create Directory? [n]|y:
    False
    >>> confirm(prompt='Create Directory?', resp=False)
    Create Directory? [n]|y: y
    True
    """
    if prompt is None:
        prompt = 'Confirm'

    if resp:
        prompt = '%s [%s]|%s: ' % (prompt, 'y', 'n')
    else:
        prompt = '%s [%s]|%s: ' % (prompt, 'n', 'y')

    while True:
        ans = raw_input(prompt)
        if not ans:
            return resp
        if ans not in ['y', 'Y', 'n', 'N']:
            print('please enter y or n.')
            continue
        if ans == 'y' or ans == 'Y':
            return True
        if ans == 'n' or ans == 'N':
            return False


def get_yaml(yamlfile):
    """
    This function retrieves a yaml file from aws-landscape
    This function is being used in drone
    :param yamlfile: The name of the yaml file
    :return: a yaml dict
    """
    # FIXME test this sub
    config_file = open("%s/etc/%s" % (os.environ['KERRIGAN_ROOT'], yamlfile), 'r')
    y = yaml.load(config_file)
    return y


def generate_password(size=8, chars=string.ascii_uppercase + string.digits):
    # FIXME somehow test the random password with rege assertion
    """
    This function generates a random password
    :param size: the length of the password
    :param chars: The character types that should be used.
    :return: a random password
    """
    return ''.join(random.choice(chars) for _ in range(size))


class StopFor(Exception): pass


def get_userdata_for_os(ostype=None):
    # FIXME not tested
    """
    This function retrieves the OS userdata that is provided by devops
    :param ostype: the ostype that is requested
    :type ostype: basestring
    :return: A string containing the userdata
    :rtype: basestring
    """
    with open("%s/etc/%s_userdata" % (os.environ['KERRIGAN_ROOT'], ostype), 'r') as user_data_file:
        userdata = user_data_file.read()
    logger.debug("Userdata is : %s" % (userdata,))
    return userdata


def get_supported_columns(service):
    """
    This function returns the supported services dicts
    :param service: the service which dict should be returned
    :type service: basestring
    :return: a dict containing data
    :rtype: dict
    """
    if service == "ec2":
        ret = ec2_columns
    elif service == "elb":
        ret = elb_columns
    elif service == "apigateway":
        ret = apigateway_columns
    elif service == "ami":
        ret = ami_columns
    elif service == "vpc":
        ret = vpc_columns
    elif service == "iam":
        ret = iam_columns
    elif service == "rds":
        ret = rds_columns
    elif service == "route53":
        ret = route53_columns
    elif service == "s3":
        ret = s3_columns
    elif service == "sg":
        ret = sg_columns
    elif service == "autoscale":
        ret = autoscale_columns
    elif service == "cloudformation":
        ret = cloudformation_columns
    elif service == "kinesis":
        ret = kinesis_columns
    else:
        logger.error("No service provided for supported columns")
        ret = None
    return ret


def parse_service_columns(service, columns):
    """
    This function parses requested columns, and only returns supported columns
    :param service: The service that should be used
    :param columns: The requested columns
    :return: a list of keys that are supported and requested
    :rtype: list
    """
    supported_columns = get_supported_columns(service=service)
    ret = []
    if isinstance(columns, basestring) and columns:
        list_from_array = string_to_array(string=columns, split_char=",")
        for l in list_from_array:
            if supported_columns.has_key(l):
                ret.append(l)
            else:
                logger.warning("Column requested is not supported: %s" % l, )
    else:
        ret = supported_columns.keys()
    return ret


def parse_file_to_json(file):
    try:
        with open(file,'r') as data:
            json_data = json.load(data)
    except IOError as e:
        logger.critical(msg="Problems with opening and loading file: %s" % (e,))
        raise IOError
    return json_data


def get_yaml(landscape_path):
    config_file = open("%s/etc/%s" % (os.environ['KERRIGAN_ROOT'], landscape_path), 'r')
    y = yaml.load(config_file)
    return y

def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return arg