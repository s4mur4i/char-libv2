from misc.Logger import logger
from misc import Misc
from core.awschecks import awschecks
from core.base import base


class awsservice(base):
    def __init__(self):
        logger.debug("Starting awsservice")

    def gw_watchdog(self, env=None):
        logger.debug("Starting gw watchdog service")
        envs = super(awsservice, self).get_needed_envs(env=env)
        a = awschecks()
        for env in envs:
            a.check_gws_in_env(env=env)
