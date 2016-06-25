from misc.Logger import logger
from wrapper.wrapper_base import wrapper_base
from botocore.exceptions import ClientError


class Lambda(wrapper_base):
    def __init__(self, session):
        """
        This function creates the initial client and resource objects
        :param session: a boto3 session object for connecting to aws
        :return: a wrapper.Lambda object for running wrapper commands
        """
        logger.debug("Starting Lambda wrapper")
        self.lambda_client = session.client(service_name="lambda")

    def upload_lambda(self, name, role, eventSourceArn, batchSize, handler,
                      memorySize, timeout, zip_path):
        """
        This function reads a local zip and uploads it to a lambda function
        :param name:
        :param role:
        :param eventSourceArn:
        :param batchSize:
        :param handler:
        :param memorySize:
        :param timeout:
        :param zip_path:
        :return:
        """
        f = open(zip_path, mode='rb')
        data = f.read()
        f.close()
        lambda_func = self.lambda_client.create_function(FunctionName=name,
                                                         Runtime='nodejs',
                                                         Role=role,
                                                         Handler=handler,
                                                         Code={'ZipFile': data},
                                                         Timeout=timeout,
                                                         MemorySize=memorySize,
                                                         Publish=True)
        super(Lambda, self).query_information(query=lambda_func)

        if eventSourceArn and not self.event_source_mapping_exists(arn=eventSourceArn, name=name):
            ret = self.lambda_client.create_event_source_mapping(EventSourceArn=eventSourceArn,
                                                                 FunctionName=name,
                                                                 Enabled=True,
                                                                 BatchSize=batchSize,
                                                                 StartingPosition='TRIM_HORIZON')
            super(Lambda, self).query_information(query=ret)
        return lambda_func

    def update_lambda(self, name, zip_path, role, handler, timeout, memorySize):
        """
        This function updates a lambda function code and config
        :param name:
        :param zip_path:
        :param role:
        :param handler:
        :param timeout:
        :param memorySize:
        :return:
        """
        f = open(zip_path, mode='rb')
        data = f.read()
        f.close()
        ret = self.lambda_client.update_function_code(FunctionName=name,
                                                      ZipFile=data,
                                                      Publish=True)
        super(Lambda, self).query_information(query=ret)
        func_ret = self.lambda_client.update_function_configuration(FunctionName=name,
                                                                    Role=role,
                                                                    Handler=handler,
                                                                    Timeout=timeout,
                                                                    MemorySize=memorySize)
        super(Lambda, self).query_information(query=func_ret)

    def get_function(self, name):
        """
        This function returns the lambda object
        :param name:
        :return:
        """
        function = self.lambda_client.get_function(FunctionName=name)
        super(Lambda, self).query_information(query=function)
        return function

    def lambda_exists(self, name):
        """
        This function tests if lambda exists
        :param name:
        :return:
        """
        try:
            self.get_function(name=name)
            return True
        except Exception as e:
            if e.response['Error']['Code'] == "ResourceNotFoundException":
                return False
            else:
                logger.error(e)
                exit(1)

    def delete_lambda(self, name):
        """
        This function deletes a lambda
        :param name:
        :return:
        """
        ret = self.lambda_client.delete_function(FunctionName=name)
        super(Lambda, self).query_information(query=ret)
        return ret

    def event_source_mapping_exists(self, arn, name):
        """
        This function tests if a event source mapping exists
        :param arn:
        :param name:
        :return:
        """
        mapping = self.get_source_mapping(arn=arn,name=name)
        if len(mapping) == 0:
            return False
        else:
            return True

    def get_source_mapping(self,arn,name):
        """
        This function returns a source mapping
        :param arn:
        :param name:
        :return:
        """
        mapping = self.lambda_client.list_event_source_mappings(EventSourceArn=arn, FunctionName=name)
        super(Lambda, self).query_information(query=mapping)
        return mapping['EventSourceMappings']

    def delete_event_source_mapping(self,uuid):
        """
        This function deletes an event source mapping
        :param uuid:
        :return:
        """
        ret = self.lambda_client.delete_event_source_mapping(UUID=uuid)
        super(Lambda, self).query_information(query=ret)
        return ret
