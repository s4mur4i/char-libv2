from misc.Logger import logger
from misc import Misc
from wrapper.wrapper_base import wrapper_base
import boto3.dynamodb.types


class Dynamodb(wrapper_base):
    def __init__(self, session):
        '''
        This function creates the initial client and resource objects
        :param session: a boto3 session object for connecting to aws
        :return: a wrapper.Dynamodb object for running wrapper commands
        '''
        logger.debug("Starting Dynamodb wrapper")
        self.dynamodb_client = session.client(service_name="dynamodb")
        self.dynamodb_resource = session.resource(service_name="dynamodb")

    def get_item(self, tablename, key, filters=None):
        """
        This function returns an item from a dynamodb table
        :param tablename: The table to use to do query
        :type tablename: string
        :param key: The primary key to filter
        :type key: dict
        :param filters: The attributes to return from the table
        :param filters: string
        :return: A dict with dynamo data
        :rtype: dict
        """
        if filters:
            resp = self.dynamodb_client.get_item(TableName=tablename, Key=key, ProjectionExpression=filters)
        else:
            resp = self.dynamodb_client.get_item(TableName=tablename, Key=key)
        super(Dynamodb, self).query_information(query=resp)
        if 'Item' in resp:
            converted_dict = dict_deserialize(item=resp['Item'])
        else:
            converted_dict = {}
        return converted_dict

    def put_item(self, tablename, item):
        """
        This function puts an item into a dynamodb table
        :param tablename:
        :param item:
        :return:
        """
        serialized_item = dict_serialize(item=item)
        resp = self.dynamodb_client.put_item(TableName=tablename, Item=serialized_item)
        super(Dynamodb, self).query_information(query=resp)
        return resp

    def describe_table(self, tablename):
        """
        This function returns information about a table
        :param tablename:
        :return:
        """
        resp = self.dynamodb_client.describe_table(TableName=tablename)
        super(Dynamodb, self).query_information(query=resp)
        return resp['Table']

    def table_exists(self, tablename):
        """
        This function tests if a table exists
        :param tablename:
        :return:
        """
        ret = True
        try:
            self.describe_table(tablename=tablename)
            logger.info(msg="Table exists %s" % (tablename,))
        except Exception as e:
            logger.info(msg="Table does not exist %s" % (tablename,))
            ret = False
        return ret

    def create_dynamo_table(self, table_name, hash_key, range_key, read_cap,
                            write_cap, enable_stream):
        """
        This function is used from usage to create dynamodb table. some vars hardcoded
        :param table_name:
        :param hash_key:
        :param range_key:
        :param read_cap:
        :param write_cap:
        :param enable_stream:
        :return: the create boto3.table object
        """
        if enable_stream:
            streamSpecification = {
                'StreamEnabled': True,
                'StreamViewType': 'NEW_AND_OLD_IMAGES'
            }
        else:
            streamSpecification = {
                'StreamEnabled': False
            }
        table = self.dynamodb_client.create_table(TableName=table_name,
                                                  AttributeDefinitions=[{
                                                      'AttributeName': hash_key,
                                                      'AttributeType': 'S'  # todo
                                                  }, {
                                                      'AttributeName': range_key,
                                                      'AttributeType': 'S'
                                                  }],
                                                  KeySchema=[{
                                                      'AttributeName': hash_key,
                                                      'KeyType': 'HASH'
                                                  }, {
                                                      'AttributeName': range_key,
                                                      'KeyType': 'RANGE'
                                                  }],
                                                  ProvisionedThroughput={
                                                      'ReadCapacityUnits': read_cap,
                                                      'WriteCapacityUnits': write_cap
                                                  },
                                                  StreamSpecification=streamSpecification)
        super(Dynamodb, self).query_information(query=table)
        waiter = self.dynamodb_client.get_waiter('table_exists')
        waiter.wait(TableName=table_name)
        return table

    def delete_dynamo_table(self, name):
        """
        This function deletes the requested table
        :param name: the table to delete
        :return: None
        """
        ret = self.dynamodb_client.delete_table(TableName=name)
        super(Dynamodb, self).query_information(query=ret)
        return ret

    def dynamo_exists(self, name):
        """
        This function checks if a dynamo table exists or not
        :param name: The name of table to check if exists
        :return: a boolean if exists or not
        """
        try:
            self.describe_table(tablename=name)
            return True
        except Exception as e:
            if e.response['Error']['Code'] == "ResourceNotFoundException":
                return False
            else:
                logger.error(e)
                exit(1)

    def update_dynamo_table(self, name, write_capacity, read_capacity):
        """
        This function update dynamo attributes
        :param name: name of table to update
        :type name: str
        :param write_capacity: the requested write capacity
        :type write_capacity:int
        :param read_capacity: the requested read capacity
        :type read_capacity: int
        :return: None
        """
        ret = self.dynamodb_client.update_table(TableName=name,
                                                ProvisionedThroughput={'ReadCapacity': read_capacity,
                                                                       'WriteCapacity': write_capacity})

        super(Dynamodb, self).query_information(query=ret)
        return ret


def dict_deserialize(item):
    """
    This function deserializes the dict to remove type information from it
    :param item: This serialized dynamo table that should be converted to dict
    :return: a normal python dict
    """
    deserializer = boto3.dynamodb.types.TypeDeserializer()
    deserialized_dict = {k: deserializer.deserialize(v) for k, v in item.items()}
    return deserialized_dict


def convert_dict(item):
    """
    This function converts a dynomdb dict to dpython dict
    :param item:
    :return:
    """
    converted = {}
    for item_key in item.keys():
        value = parse_dynamo_value(value=item[item_key])
        converted[item_key] = value
    return converted


def parse_dynamo_value(value):
    """
    This function parses the value to convert it to simple value
    :param value:
    :return:
    """
    key = value.keys()[0]
    ret = None
    if key == "S":
        ret = value[key]
    elif key == "L":
        ret = []
        for item in value[key]:
            ret.append(parse_dynamo_value(item))
    elif key == "M":
        ret = convert_dict(item=value[key])
    else:
        logger.error("Key in dynamodb is not handled by kerrigan parser: %s" % (key,))
    return ret


def dict_serialize(item):
    """
    This function serializes the dict to add type information to it
    :param item: the dict to serialize
    :return: a serialized dynamodb dict
    """
    serializer = boto3.dynamodb.types.TypeSerializer()
    serialized_dict = {k: serializer.serialize(v) for k, v in item.items()}
    return serialized_dict
