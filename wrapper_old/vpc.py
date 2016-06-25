from misc.Logger import logger
from misc import Misc
import boto3


class Vpc(object):
    def __init__(self, region='us-east-1'):
        logger.debug("Starting EC2Class for vpc")
        self.boto3 = boto3.client('ec2', region_name=region)
        self.region = region
