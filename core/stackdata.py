from misc.Logger import logger
from misc import Misc
from core.base import base


class stackdata(base):
    def __init__(self, session):
        logger.debug("Started stackdata object")
        self.session = session

    def get_stack_data(self, puppet_role, xively_service):
        from wrapper.dynamodb import Dynamodb
        dynamodb = Dynamodb(session=self.session)
        landscape_tablename = Misc.landscape_dynamo_table_name
        if dynamodb.table_exists(tablename=landscape_tablename):
            query_key = {"puppet_role": {"S": puppet_role}, "xively_service": {"S": xively_service}}
            stack_data = dynamodb.get_item(tablename=landscape_tablename, key=query_key)
        else:
            stack_data = {}
        return stack_data
