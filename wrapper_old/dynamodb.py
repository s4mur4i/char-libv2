import boto3
from misc.Logger import logger
from misc import Misc


class DynamoDB(object):
    def __init__(self, region='us-east-1'):
        logger.debug("Starting DynamoDB Class for dynamodb")
        self.attribute_definitions = [{'AttributeName': 'id', 'AttributeType': 'S'}, ]
        self.table_name = "dev-xaf-test"
        self.key_schema = [{'AttributeName': 'id', 'KeyType': 'HASH'}, ]
        self.local_secondary_indexes = [
            {'IndexName': 'test-local-index', 'KeySchema': [{'AttributeName': 'id', 'KeyType': 'HASH'}, ],
             'Projection': {'ProjectionType': 'ALL', 'NonKeyAttributes': ['help', ]}, }, ]
        self.global_secondary_indexes = [
            {'IndexName': 'test-global-index', 'KeySchema': [{'AttributeName': 'id', 'KeyType': 'HASH'}, ],
             'Projection': {'ProjectionType': 'ALL', 'NonKeyAttributes': ['help', ]},
             'ProvisionedThroughput': {'ReadCapacityUnits': 123, 'WriteCapacityUnits': 123}}, ]
        self.provisioned_throughput = {'ReadCapacityUnits': 123, 'WriteCapacityUnits': 123}
        self.stream_specification = {'StreamEnabled': False, 'StreamViewType': 'KEYS_ONLY'}

        self.dynamodb = boto3.client('dynamodb', region_name=region)

    def create_dynamodb_table(self, attribute_definitions=None, table_name=None, key_schema=None,
                              provisionied_throughput=None):
        resp = self.dynamodb.create_table(AttributeDefinitions=self.attribute_definitions, TableName=self.table_name,
                                          KeySchema=self.key_schema, ProvisionedThroughput=self.provisioned_throughput)
        return resp

    def describe_dynamodb_table(self, table_name=None):
        resp = self.dynamodb.describe_table(TableName=table_name)
        return resp

    def get_dynamodb_tables_by_environment(self, environment=None):
        if environment == "None":
            resp = self.dynamodb.list_tables()
            return resp['TableNames']
        else:
            resp = self.dynamodb.list_tables()
            tables = filter(lambda k: environment in k, resp)
            return tables['TableNames']
