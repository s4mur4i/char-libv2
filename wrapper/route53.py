from misc.Logger import logger
from wrapper.wrapper_base import wrapper_base


class Route53(wrapper_base):
    def __init__(self, session):
        """
        This function creates the initial client and resource objects
        :param session: a boto3 session object for connecting to aws
        :return: a wrapper.Route53 object for running wrapper commands
        """
        logger.debug("Starting route53 wrapper")
        self.route53_client = session.client(service_name="route53")
        self.route53_resource = session.resource(service_name="route53")
