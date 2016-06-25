import boto3

from misc.Logger import logger
from misc import Misc


class Rds(object):
    def __init__(self, region='us-east-1'):
        logger.debug("Starting EC2Class for rds")
        self.boto3 = boto3.client('rds', region_name=region)

    def get_db_parameter_group(self, name=None):
        if name:
            resp = self.boto3.describe_db_parameters(DBParameterGroupName=name)
        else:
            resp = self.boto3.describe_db_parameters()
        ret = []
        for param in resp['Parameters']:
            ret.append(param)
        return ret

    def get_db_instances(self, filters=None):
        resp = self.boto3.describe_db_instances()
        r = []
        for rds in resp['DBInstances']:
            arn = Misc.generate_arn(service="rds", resourcetype="db", name=rds.get('DBInstanceIdentifier'))
            rds['ARN'] = arn
            rds['Tags'] = self.get_tags_for_rds(name=arn)
            r.append(rds)
        ret = []
        if filters:
            # FIXME currently filters are not implemented
            # resp = self.boto3.describe_db_instances(Filters=filters)
            for rds in r:
                if rds_instance_filters(rds=rds, filters=filters):
                    ret.append(rds)
        else:
            ret = r
        return ret

    def get_tags_for_rds(self, name=None):
        resp = self.boto3.list_tags_for_resource(ResourceName=name)
        return resp['TagList']


def rds_instance_filters(rds=None, filters=None):
    for f in filters:
        logger.debug("Filter investigation %s" % f, )
        if f['Name'] == "VpcId":
            if f['Values'][0] == rds.get('DBSubnetGroup').get('VpcId'):
                logger.info("This is the VPC we need for rds %s" % rds.get('DBSubnetGroup').get('VpcId'), )
            else:
                logger.debug("RDS is in wrong VPC")
                return False
        if f['Name'] == "tag:Name":
            if 'Tags' in rds:
                logger.debug("RDS instance has tags")
                tag_name = Misc.get_value_from_array_hash(dictlist=rds['Tags'], key='Name')
                if f['Values'][0] == tag_name:
                    logger.info("Tag name is same")
                    continue
            return False
    return True
