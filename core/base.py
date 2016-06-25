from misc.Logger import logger
from misc.Misc import cli_argument_parse
from wrapper.vpc import Vpc
from wrapper.session import Session


class base(object):
    def __init__(self):
        logger.debug("Started base object")

    def get_needed_envs(self, env=None):
        '''
        This sub returns all valid environments, and if nothing is requested returns all in account
        :param env: a comma seperated list of environments to check
        :type env: string with comma
        :return: list of valid environments
        :rtype: list
        '''
        v = Vpc()
        active = v.get_active_envs()
        if env:
            logger.debug("Env is defined, parsing %s" % env,)
            e = env.split(',')
            envs = []
            for i in e:
                if i in active:
                    envs.append(i)
        else:
            logger.debug("No specific env environment was requested, providing all")
            envs = active
        logger.info("Going to iterate over envs: %s" % envs,)
        return envs

    def check_stack_syntax(self,stack=None):
        '''
        This sub is used to validate if stack syntax is correct.
        :param stack: The stack/puppet_role that needs to be validated
        :type stack: string
        :return: Nothing, exit if stack/puppet_role has underscore
        '''
        if "_" in stack:
            logger.error("Stack name should not contain '_'")
            exit(666)


    def get_account_information(self):
        '''
        This def returns the session object for boto3, cli arguments provided and used and logger_arguments
        :rtype: Dict
        :return: Session object for wrapper and core class
        '''
        [arguments, logger_arguments] = cli_argument_parse()
        logger.debug("Arguments provided: %s" % arguments, )
        s = Session(arguments=arguments).session
        return {'session': s, 'logger_arguments': logger_arguments, 'cli_arguments': arguments}
