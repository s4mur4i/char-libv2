import boto3

from misc.Logger import logger
from misc import Misc
from wrapper.vpc import Vpc
from wrapper.ec2 import Ec2


class Elb(object):
    def __init__(self, region='us-east-1'):
        logger.debug("Starting EC2Class for vpc")
        self.elb = boto3.client('elb', region_name=region)
        self.region = region

    def info_all(self):
        elbs = self.get_all_elbs()
        result = []
        yaml = Misc.get_aws_yaml(yaml_file="elb")
        V = Vpc()
        for lb in elbs:
            tmp = lb['LoadBalancerName'].split('-')
            if len(tmp) >= 3:
                elb_env = tmp.pop(0)
                short_env = tmp.pop(0)
                elb_stack = "-".join(tmp)
            elb_facing = lb['Scheme']
            if elb_stack in yaml and elb_facing in yaml[elb_stack]:
                yaml_info = yaml[elb_stack][elb_facing]
                v = V.get_vpc_from_env(env=elb_env)
                domain = Misc.get_value_from_array_hash(dictlist=v.get('Tags'), key="Domain")
                if elb_facing == "internet-facing":
                    elb_dns_name = yaml_info['dns'] + "." + Misc.change_domain_to_local(domain=domain)
                elif elb_facing == "internal":
                    elb_dns_name = yaml_info['dns'] + "." + Misc.change_domain_to_local(domain=domain)
            else:
                elb_dns_name = None
            info = {}
            if elb_dns_name is not None:
                info['DNS cname'] = elb_dns_name
            else:
                info['DNS cname'] = "This elb is not in automatisation framework. Will be decomissioned"
            info['Xively_service'] = Misc.get_value_from_array_hash(dictlist=lb.get('Tags'), key="Xively_service")
            info['Puppet_role'] = Misc.get_value_from_array_hash(dictlist=lb.get('Tags'), key="Puppet_role")
            info['Env'] = Misc.get_value_from_array_hash(dictlist=lb.get('Tags'), key="Environment")
            info['Real endpoint'] = lb['DNSName']
            info['Vpcid'] = lb['VPCId']
            info['Name'] = lb['LoadBalancerName']
            info['CreateTime'] = lb['CreatedTime'].strftime("%Y-%m-%d %H:%M")
            info['Facing'] = elb_facing
            info['Availability Zones'] = lb['AvailabilityZones']
            info['Securitygroups'] = lb['SecurityGroups']
            instance = []
            for i in lb['Instances']:
                instance.append(i['InstanceId'])
            info['InstanceIds'] = instance
            listen = []
            for listener in lb['ListenerDescriptions']:
                listener = listener['Listener']
                listen.append(
                    "%s-%s-%s" % (listener['LoadBalancerPort'], listener['InstancePort'], listener['Protocol']))
            info['From-To-Protocol'] = listen
            result.append(info)
        return result

    def get_all_elbs(self, elbs=None, with_tag=True):
        if elbs:
            resp = self.elb.describe_load_balancers(LoadBalancerNames=elbs)
        else:
            resp = self.elb.describe_load_balancers()
        result = []
        for lb in resp['LoadBalancerDescriptions']:
            logger.debug("Gathering info on %s" % (lb['LoadBalancerName'],))
            if with_tag:
                tags = self.get_elb_tags(name=lb['LoadBalancerName'])
                lb['Tags'] = tags
            result.append(lb)
            logger.debug("ELb information: %s" % (lb,))
        return result

    def get_elb_tags(self, name=None):
        while True:
            try:
                resp = self.elb.describe_tags(LoadBalancerNames=[name])
            except Exception as e:
                logger.warning("ELB describeTags through an error, retrying")
                continue
            break
        tags = resp['TagDescriptions'][0]['Tags']
        return tags

    def sort_elbs_to_vpc(self):
        elbs = self.get_all_elbs()
        ret = {}
        for elb in elbs:
            vpcid = elb.get('VPCId')
            if vpcid not in ret:
                ret[vpcid] = []
            ret[vpcid].append(elb)
        return ret

    def create_elb(self, name=None, listeners=None, scheme=None, tags=None, env=None, sg_name=None):
        subnets = self.get_subnets_for_elb(scheme=scheme, env=env)
        yaml_tags = Misc.get_yaml_tags_for_sub(sub="elb")
        lb_name = self.generate_elb_name(stack=name, facing=scheme, env=env)
        for y in yaml_tags:
            logger.debug("Checking if tag exists %s" % y, )
            if y == "Environment":
                tags.append({'Key': y, 'Value': env})
                continue
            if y == "Name":
                tags.append({'Key': y, 'Value': lb_name})
                continue
            t = Misc.get_value_from_array_hash(dictlist=tags, key=y)
            if t is None:
                tags.append({'Key': y, 'Value': ""})
        sgs = self.get_sgs_for_elb(env=env, name=sg_name)
        self.elb.create_load_balancer(LoadBalancerName=lb_name, Scheme=scheme, Tags=tags, SecurityGroups=sgs,
                                      Subnets=subnets, Listeners=listeners)
        return lb_name

    def get_subnets_for_elb(self, scheme=None, env=None):
        vpc = Vpc()
        v = vpc.get_vpc_from_env(env=env)
        azs = Misc.get_azs_from_yaml(region=self.region)
        if scheme == "internal":
            avail = "private"
        else:
            avail = "public"
        res = []
        sub = vpc.get_all_subnets(
            filters=[{'Name': 'tag:Availability', 'Values': [avail]}, {'Name': 'availabilityZone', 'Values': azs},
                     {'Name': 'vpc-id', 'Values': [v.get('VpcId')]}])
        for s in sub:
            logger.debug("Adding sub: %s" % sub, )
            res.append(s.get('SubnetId'))
        logger.debug("Subnets for elb are: %s" % res, )
        return res

    def get_sgs_for_elb(self, env=None, name=None):
        ec2 = Ec2()
        vpc = Vpc()
        v = vpc.get_vpc_from_env(env=env)
        sgs = ec2.get_security_groups(
            filters=[{'Name': 'tag:ELB', 'Values': [name]}, {'Name': 'vpc-id', 'Values': [v.get('VpcId')]}])
        res = []
        for sg in sgs:
            res.append(sg.get('GroupId'))
        logger.debug("Sgs for the elb are %s" % res, )
        return res

    def generate_elb_name(self, stack=None, facing=None, env=None):
        if facing == "internal":
            avail = "int"
        else:
            avail = "pub"
        lb_name = env + "-" + avail + "-" + stack
        if len(lb_name) > 32:
            logger.error("ELB name is longer than 32 chars. there will be an issue creating the elb")
        logger.info("ELB name is going to be: %s" % lb_name, )
        return lb_name

    def get_elbs_from_ssl_cert(self, certid=None):
        elbs = self.get_all_elbs()
        if certid:
            res = []
            for elb in elbs:
                if listener_has_cert(cert=certid, listeners=elb['ListenerDescriptions']):
                    res.append(elb)
                else:
                    logger.debug("Elb does not have cert attached.")
            return res
        else:
            res = {}
            for elb in elbs:
                certs = elb_listener_cert(elb['ListenerDescriptions'])
                for cert in certs:
                    if cert in res:
                        res[cert].append(elb)
                    else:
                        res[cert] = [elb]
            return res

    def set_elb_ssl_cert(self, elb_name=None, port=None, cert=None):
        ret = self.elb.set_load_balancer_listener_ssl_certificate(LoadBalancerName=elb_name, LoadBalancerPort=port,
                                                                  SSLCertificateId=cert)
        logger.debug("Ret is %s" % ret, )
        return ret

    def get_elb_from_env_and_tag(self, env=None, tags=None, facing=None):
        elbs = self.get_elb_from_env(env=env)
        ret = []
        for elb in elbs:
            if elb.get('Scheme') == facing:
                if compare_elb_tags(elb_tags=elb.get('Tags'), tags=tags):
                    ret.append(elb)
                else:
                    continue
        return ret

    def get_elb_from_env(self, env=None):
        v = Vpc()
        vpc = v.get_vpc_from_env(env=env)
        elbs = self.get_all_elbs()
        ret = []
        for elb in elbs:
            if elb['VPCId'] == vpc.get('VpcId'):
                ret.append(elb)
        logger.debug("Elbs in env %s : %s" % (env, ret))
        return ret

    def configure_health_check(self, name=None, healthcheck=None):
        ret = self.elb.configure_health_check(LoadBalancerName=name, HealthCheck=healthcheck)
        logger.debug("Ret is %s" % ret, )

    def add_instance_to_elb(self, name=None, instances=None, dryrun=False):
        if dryrun:
            logger.warning("Dryrun requested: elb: %s, instances: %s" % (name, instances))
            return True
        ret = self.elb.register_instances_with_load_balancer(LoadBalancerName=name, Instances=instances)
        logger.debug("Ret is: %s" % ret, )

    def describe_lb_attribs(self, name=None):
        ret = self.elb.describe_load_balancer_attributes(LoadBalancerName=name)
        return ret['LoadBalancerAttributes']

    def modify_lb_atrribs(self, name=None, attribs=None):
        ret = self.elb.modify_load_balancer_attributes(LoadBalancerName=name, LoadBalancerAttributes=attribs)
        # FIXME validate if change has gone through?
        return ret['LoadBalancerAttributes']


def compare_elb_tags(elb_tags=None, tags=None):
    for tag in tags:
        elb_tag_value = Misc.get_value_from_array_hash(dictlist=elb_tags, key=tag)
        if elb_tag_value == tags[tag]:
            continue
        else:
            return False
    return True


def elb_listener_cert(listeners=None):
    res = []
    for listener in listeners:
        if 'Listener' in listener and 'SSLCertificateId' in listener['Listener']:
            res.append(listener['Listener']['SSLCertificateId'])
    logger.debug("Returning certs: %s" % res, )
    return res


def listener_has_cert(listeners=None, cert=None):
    for listener in listeners:
        if 'Listener' in listener and 'SSLCertificateId' in listener['Listener']:
            logger.info("listener has certificate ID, inspecting")
            if listener['Listener']['SSLCertificateId'] == cert:
                logger.info("Certificate is used for elb")
                return True
            else:
                logger.debug("ELB listener has different cert")
        else:
            logger.debug("ELB has no cert or listener")
    return False
