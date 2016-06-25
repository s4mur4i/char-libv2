import boto3

from misc.Logger import logger
from misc import Misc
from wrapper.vpc import Vpc


class S3(object):
    def __init__(self, region='us-east-1'):
        logger.debug("Starting EC2Class for s3")
        self.s3 = boto3.client('s3', region_name=region)
        self.region = region

    def list_buckets(self):
        resp = self.s3.list_buckets()
        return resp['Buckets']

    def get_bucket_acl(self, name):
        resp = self.s3.get_bucket_acl(Bucket=name)
        return resp

    def get_bucket_location(self, name):
        resp = self.s3.get_bucket_location(Bucket=name)
        if resp['LocationConstraint'] is None:
            # This bucket is in us-east-1
            return 'us-east-1'
        return resp['LocationConstraint']

    def get_bucket_lifecycle(self, name):
        try:
            resp = self.s3.get_bucket_lifecycle(Bucket=name)
        except Exception as e:
            if "An error occurred (NoSuchLifecycleConfiguration)" in e:
                logger.warning("Bucket %s has no Lifecycle configuration" % (name,))
            else:
                logger.error("%s" % e, )
            return None
        return resp['Rules']

    def get_bucket_logging(self, name):
        resp = self.s3.get_bucket_logging(Bucket=name)
        if 'LoggingEnabled' in resp:
            ret = resp['LoggingEnabled']
        else:
            ret = None
        return ret

    def get_bucket_policy(self, name):
        try:
            resp = self.s3.get_bucket_policy(Bucket=name)
        except Exception as e:
            if "An error occurred (NoSuchBucketPolicy)" in e:
                logger.warning("Bucket %s has no policy configuration" % (name,))
            else:
                logger.error("%s" % e, )
            return None
        return resp

    def get_bucket_replication(self, name):
        try:
            resp = self.s3.get_bucket_replication(Bucket=name)
        except Exception as e:
            if "An error occurred (ReplicationConfigurationNotFoundError)" in e:
                logger.warning("Bucket %s has no replication configuration" % (name,))
            else:
                logger.error("%s" % e, )
            return None
        return resp

    def get_bucket_tagging(self, name):
        try:
            resp = self.s3.get_bucket_tagging(Bucket=name)
        except Exception as e:
            if "An error occurred (NoSuchTagSet)" in e:
                logger.warning("Bucket %s has no Tag configuration" % (name,))
            else:
                logger.error("%s" % e, )
            return None
        return resp['TagSet']

    def list_objects(self, bucket_name):
        resp = self.s3.list_objects(Bucket=bucket_name)
        return resp['Contents']

    def get_object(self, bucket_name, key):
        try:
            resp = self.s3.get_object(Bucket=bucket_name, Key=key)
        except Exception as e:
            if "An error occurred (NoSuchKey)" in e:
                logger.warning("Object %s in s3 bucket %s does not exist" % (key, bucket_name))
            else:
                logger.error("%s" % e, )
            return None
        return resp

    def put_object(self, bucket_name, key):
        resp = self.s3.put_object(Bucket=bucket_name, Key=key)
        return resp

    def create_folder(self, bucket_name, key):
        resp = self.put_object(bucket_name=bucket_name, key=key)
        return resp
