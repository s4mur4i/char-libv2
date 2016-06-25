from misc.Logger import logger
from wrapper.wrapper_base import wrapper_base


class Rds(wrapper_base):
    def __init__(self, session):
        """
        This function creates the initial client and resource objects
        :param session: a boto3 session object for connecting to aws
        :return: a wrapper.Rds object for running wrapper commands
        """
        logger.debug("Starting Rds wrapper")
        self.rds_client = session.client(service_name="rds")
        self.rds_resource = session.resource(service_name="rds")
