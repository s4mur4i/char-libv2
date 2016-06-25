from misc.Logger import logger
from wrapper.wrapper_base import wrapper_base


class S3(wrapper_base):
    def __init__(self, session):
        '''
        This function creates the initial client and resource objects
        :param session: a boto3 session object for connecting to aws
        :return: a wrapper.S3 object for running wrapper commands
        '''
        logger.debug("Starting iam wrapper")
        self.s3_client = session.client(service_name="s3")
        self.s3_resource = session.resource(service_name="s3")

    def create_bucket(self, name, location=None,dryrun=False):
        """
        This function creates an s3 bucket
        :param name: This should be the name of the bucket
        :type name: basestring
        :param location: the location where the bucket should be constrained to, not used if us-east-1 value
        :type location: basestring
        :return:
        """
        if dryrun:
            logger.warning("Dryrun requested for creating bucket %s" % (name,))
            return None
        if location and location != "us-east-1":
            resp = self.s3_client.create_bucket(Bucket=name, CreateBucketConfiguration={'LocationConstraint': location})
        else:
            resp = self.s3_client.create_bucket(Bucket=name)
        super(S3, self).query_information(query=resp)
        resp.pop('ResponseMetadata')
        return resp
