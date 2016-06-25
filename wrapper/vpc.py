from misc.Logger import logger
from misc import Misc
from wrapper.wrapper_base import wrapper_base


class Vpc(wrapper_base):
    def __init__(self, session):
        """
        This function creates the initial client and resource objects
        :param session: a boto3 session object for connecting to aws
        :return: a wrapper.Vpc object for running wrapper commands
        """
        logger.debug("Starting vpc wrapper")
        self.vpc_client = session.client(service_name="ec2")
        self.vpc_resource = session.resource(service_name="ec2")

    def get_active_envs(self, env=None):
        """
        This function returns an array with the active environemnts in the account
        :param env: a comma seperated list of environments that should be validated
        :type env: basestring
        :return: An array with active environments
        :rtype: list
        """
        vpcs = self.get_all_vpcs()
        envs = []
        for vpc in vpcs:
            cur = Misc.get_value_from_array_hash(dictlist=vpc['Tags'], key='Environment')
            if cur != "":
                envs.append(cur)
            else:
                logger.warning("Vpc has no Environment tag: %s" % (vpc.id))
        if env:
            envs = [env]
        logger.debug("Current envs: " + str(envs))
        return envs

    def get_all_vpcs(self, filters=None, vpcid=None):
        """
        This function returns or filters all vpcs
        :param filters: A dict list with  the boto3 filters
        :param vpcid: A vpcid that should only be returned
        :return: A list of boto3.Vpc objects
        """
        if vpcid:
            response = self.vpc_client.describe_vpcs(VpcIds=vpcid)
        elif filters:
            response = self.vpc_client.describe_vpcs(Filters=filters)
        else:
            response = self.vpc_client.describe_vpcs()
        super(Vpc, self).query_information(query=response)
        ret = []
        for vpc in response['Vpcs']:
            ret.append(vpc)
        return ret

    def get_vpc_from_env(self, env):
        """
        This function returns the vpc object from an environment tag string
        :param env: The environment that should be returned
        :return: A boto3.Vpc object with the requested environment
        """
        vpcs = self.get_all_vpcs(filters=[{"Name": "tag:Environment", 'Values': [env]}])
        if len(vpcs) == 1:
            return vpcs[0]
        else:
            logger.error("Multiple envs found: %s" % (env,))
            raise ValueError

    def get_all_subnets(self, filters=None, subnetids=None):
        """
        This function returns all subnets, or filters them as requested
        :param filters: A dict list with the boto3 filters
        :param subnetids: A list of subnetids that should only be returned
        :return: A list of subnets that were requested
        """
        if subnetids:
            response = self.vpc_client.describe_subnets(SubnetIds=subnetids)
        elif filters:
            response = self.vpc_client.describe_subnets(Filters=filters)
        else:
            response = self.vpc_client.describe_subnets()
        result = []
        for s in response['Subnets']:
            allowed = Misc.get_value_from_array_hash(dictlist=s.get('Tags'), key="Allowed")
            if Misc.str2bool(allowed):
                result.append(s)
        logger.debug("Allowed az subnets are: %s" % (result,))
        return result

    def information_vpc(self, filters):
        if filters:
            vpcs = self.get_all_vpcs(filters=filters)
        else:
            vpcs = self.get_all_vpcs(filters=filters)
        return vpcs
