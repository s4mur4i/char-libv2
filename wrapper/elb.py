from misc.Logger import logger
from wrapper.wrapper_base import wrapper_base


class Elb(wrapper_base):
    def __init__(self, session):
        """
        This function creates the initial client and resource objects
        :param session: a boto3 session object for connecting to aws
        :return: a wrapper.Elb object for running wrapper commands
        """
        logger.debug("Starting Elb wrapper")
        self.elb_client = session.client(service_name="elb")

    def information_elbs(self, filters):
        elbs = self.get_all_elbs()
        for elb in elbs:
            elb['instance_num'] = len(elb['Instances'])
            if 'CanonicalHostedZoneName' not in elb:
                elb['CanonicalHostedZoneName'] = None
            instance = []
            for inst in elb['Instances']:
                instance.append(inst['InstanceId'])
            elb['Instances'] = instance
        return elbs

    def get_all_elbs(self, elbs=None, with_tag=True):
        if elbs:
            resp = self.elb_client.describe_load_balancers(LoadBalancerNames=elbs)
        else:
            resp = self.elb_client.describe_load_balancers()
        super(Elb, self).query_information(query=resp)
        result = []
        for lb in resp['LoadBalancerDescriptions']:
            logger.debug("Gathering info on %s" % (lb['LoadBalancerName'],))
            if with_tag:
                tags = self.get_elb_tags(name=lb['LoadBalancerName'])
                lb['Tags'] = tags
            result.append(lb)
            logger.debug("ELb information: %s" % (lb,))
        return result

    def get_elb_tags(self, name):
        while True:
            try:
                resp = self.elb_client.describe_tags(LoadBalancerNames=[name])
            except Exception as e:
                logger.warning("ELB describeTags through an error, retrying")
                continue
            break
        super(Elb, self).query_information(query=resp)
        tags = resp['TagDescriptions'][0]['Tags']
        return tags
