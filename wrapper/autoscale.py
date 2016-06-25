from misc.Logger import logger
from wrapper.wrapper_base import wrapper_base


class Autoscale(wrapper_base):
    def __init__(self, session):
        """
        This function creates the initial client and resource objects
        :param session: a boto3 session object for connecting to aws
        :return: a wrapper.Autoscale object for running wrapper commands
        """
        logger.debug("Starting Autoscale wrapper")
        self.autoscale_client = session.client(service_name="autoscale")
        self.autoscale_resource = session.resource(service_name="autoscale")
