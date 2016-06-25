from misc.Logger import logger


class wrapper_base(object):
    def __init__(self):
        logger.debug("Started wrapper_base object")

    def query_information(self, query):
        '''
        This function is used to print debug information about a query, to see if it was succesful or not
        :param query: The boto3 query
        :return: Query with removed metadata
        '''
        if query['ResponseMetadata']['HTTPStatusCode'] == 201:
            logger.debug("Resource was succesfully created")
            logger.info("Query RequestID: %s, HTTPStatusCode: %s" % (
                query['ResponseMetadata']['RequestId'], query['ResponseMetadata']['HTTPStatusCode']))
        elif query['ResponseMetadata']['HTTPStatusCode'] == 202:
            logger.debug('Request accepted but processing later.')
            logger.info("Query RequestID: %s, HTTPStatusCode: %s" % (
                query['ResponseMetadata']['RequestId'], query['ResponseMetadata']['HTTPStatusCode']))
        elif query['ResponseMetadata']['HTTPStatusCode'] == 204:
            logger.debug('Request done but no content returned.')
            logger.info("Query RequestID: %s, HTTPStatusCode: %s" % (
                query['ResponseMetadata']['RequestId'], query['ResponseMetadata']['HTTPStatusCode']))
        elif query['ResponseMetadata']['HTTPStatusCode'] != 200:
            logger.warning('There was an issue with request.')
            logger.warning("Query RequestID: %s, HTTPStatusCode: %s" % (
                query['ResponseMetadata']['RequestId'], query['ResponseMetadata']['HTTPStatusCode']))
        else:
            logger.debug("Request had no issues")
            logger.debug("Query RequestID: %s, HTTPStatusCode: %s" % (
                query['ResponseMetadata']['RequestId'], query['ResponseMetadata']['HTTPStatusCode']))
        query.pop('ResponseMetadata')
        if 'NextToken' in query:
            logger.error("Token is present. Paging needs to be implemented")
        return query
