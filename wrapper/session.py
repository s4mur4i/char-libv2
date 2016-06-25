from misc.Logger import logger
import boto3.session

class Session(object):
    def __init__(self, arguments):
        """
        This function creates the initial client and resource objects
        :param arguments: Arguments for a boto3 session object
        :type arguments: dict
        :return: a boto3.session object for wrapper commands
        """
        logger.debug("Starting Session object")
        self.session = boto3.session.Session(**arguments)
