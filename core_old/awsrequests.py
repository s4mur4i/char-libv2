import os

import yaml

from misc.Logger import logger
from misc import Misc
from wrapper.ec2 import Ec2
from wrapper.vpc import Vpc
from wrapper.elb import Elb
from wrapper.s3 import S3
from wrapper.iam import Iam
from wrapper.route53 import Route53
from wrapper.autoscaling import AutoScaling
from wrapper.cloudwatch import CloudWatch
from core.base import base


class awsrequests(base):
    def __init__(self):
        logger.debug("Starting awsrequests")
        try:
            config_file = open("%s/etc/aws.conf" % (os.environ['KERRIGAN_ROOT'],), 'r')
            self.yaml = yaml.load(config_file)
        except IOError as e:
            logger.error("aws.conf I/O error({0}): {1}".format(e.errno, e.strerror))
        self.owner = self.yaml['owner']

    def get_envs(self):
        v = Vpc()
        return v.get_active_envs()

    def get_image_stacks(self):
        e = Ec2()
        return e.get_active_images_stacks()

    def info_all(self, filter=None):
        e = Ec2()
        instances = e.get_all_instances(filters=filter)
        output = []
        for i in instances:
            model = Misc.parse_instance(i)
            output.append(model)
        return output

    def start_instances(self, environment=None, puppet_role=None, xively_service=None, dry_run=None):
        filters = [{'Name': 'tag:Environment', 'Values': [environment]},
                   {'Name': 'tag:Puppet_role', 'Values': [puppet_role]}]
        if xively_service:
            filters.append({'Name': 'tag:Xively_service', 'Values': [xively_service]})
        e = Ec2()
        res = e.get_all_instances(filters=filters)
        candidate_ids = []
        for instance in res:
            if instance['State']['Name'] == 'stopped':
                candidate_ids.append(instance['InstanceId'])
        if len(candidate_ids) == 0:
            logger.warning("Couldn't find any instances to start")
            return []
        if not dry_run:
            logger.info("Instances would start: {0}".format(candidate_ids))
            res = e.start_instances(instance_ids=candidate_ids)
            if not ('StartingInstances' in res):
                logger.error("No instance started, error happened, result:{0}".format(res))
                return []
            result = []
            for instance in res['StartingInstances']:
                result.append({'InstanceId': instance['InstanceId'], 'State': instance['CurrentState']['Name']})
            return result

        else:
            logger.info("Instances would start: {0}".format(candidate_ids))
            return []

    def query_ips(self, environment=None, puppet_role=None, xively_service=None):
        filters = []
        if environment:
            filters.append({'Name': 'tag:Environment', 'Values': [environment]})
        if puppet_role:
            filters.append({'Name': 'tag:Puppet_role', 'Values': [puppet_role]})
        if xively_service:
            filters.append({'Name': 'tag:Xively_service', 'Values': [xively_service]})
        e = Ec2()
        instances = e.get_all_instances(filters=filters)
        ips = []
        for instance in instances:
            if instance['State']['Name'] == 'running':
                ips.append({'Public': instance['PublicIpAddress'] if 'PublicIpAddress' in instance else '-',
                            'Private:': instance['PrivateIpAddress'] if 'PrivateIpAddress' in instance else '-'})
        return ips

    def elb_info_all(self):
        e = Elb()
        result = e.info_all()
        return result

    def get_console(self):
        e = Ec2()
        out = e.get_console_output(instance_id='i-c25879ed')
        print out

    def server_certificates_info_all(self):
        i = Iam()
        e = Elb()
        out = i.get_server_certs()
        elbs = e.get_elbs_from_ssl_cert()
        for cert in out:
            if cert['Arn'] in elbs:
                list = []
                for elb in elbs[cert['Arn']]:
                    list.append(elb.get('LoadBalancerName'))
                cert['ELB'] = list
            else:
                cert['ELB'] = []
        return out

    def server_certificate_upload(self, cert_name=None, pub_key=None, priv_key=None, cert_chain=None):
        i = Iam()
        if pub_key and os.path.isfile(pub_key):
            with open(pub_key, "r") as pub_key_fh:
                pub_key = pub_key_fh.read()
        logger.info("Read pub_key to internal variable: %s" % pub_key, )
        if priv_key and os.path.isfile(priv_key):
            with open(priv_key, "r") as priv_key_fh:
                priv_key = priv_key_fh.read()
        logger.info("Read priv_key to internal variable: %s" % priv_key, )
        if cert_chain and os.path.isfile(cert_chain):
            with open(cert_chain, "r") as cert_chain_fh:
                cert_chain = cert_chain_fh.read()
            logger.debug("Read cert_chain to internal variable: %s" % cert_chain, )
        out = i.upload_server_cert(cert_name=cert_name, pub_key=pub_key, priv_key=priv_key, cert_chain=cert_chain)
        print "ServerCertificateId: %s" % out['ServerCertificateMetadata']['ServerCertificateId']

    def server_certificate_delete(self, cert_name=None):
        i = Iam()
        i.delete_server_certs(cert_name=cert_name)

    def server_certficate_update(self, domain=None, intermediate=False):
        i = Iam()
        e = Elb()
        old_name = "old." + domain
        i.update_server_cert(cert_name=old_name, new_name=domain)
        logger.debug("Rename certificate")
        i.update_server_cert(cert_name=domain, new_name=old_name)
        logger.debug("Gathering certificates informations")
        # We should query old certs, to test if they have been moved, and it is not an incorrect call being made
        old_cert = Misc.get_cert_body(name=old_name)
        old_key = Misc.get_cert_body(name=old_name, type="key")
        new_cert = Misc.get_cert_body(name=domain)
        new_key = Misc.get_cert_body(name=domain, type="key")
        logger.debug("Uploading new certificate for domain")
        if intermediate:
            inter_body = Misc.get_cert_body(domain="intermediate")
            i.upload_server_cert(cert_name=domain, pub_key=new_cert, priv_key=new_key, cert_chain=inter_body)
        else:
            i.upload_server_cert(cert_name=domain, pub_key=new_cert, priv_key=new_key)
        elbs = e.get_elbs_from_ssl_cert()
        old_object = i.get_server_cert(name=old_name)
        new_object = i.get_server_cert(name=domain)
        if old_object['ServerCertificateMetadata']['Arn'] in elbs:
            move_elbs = elbs[old_object['ServerCertificateMetadata']['Arn']]
        else:
            move_elbs = []
        for elb in move_elbs:
            logger.info("Migrating ELB %s" % elb.get('LoadBalancerName'))
            ports = ssl_ports_in_elb(elb=elb)
            for port in ports:
                logger.debug('Migrating port %s' % port, )
                e.set_elb_ssl_cert(elb_name=elb.get('LoadBalancerName'), port=port,
                                   cert=new_object['ServerCertificateMetadata']['Arn'])
        logger.info("Deleting old cert")
        i.delete_server_certs(cert_name=old_name)
        logger.echo("Updated certificate to new one.")

    def route53_info(self, env=None):
        envs = super(awsrequests, self).get_needed_envs(env=env)
        v = Vpc()
        r = Route53()
        res = []
        for environment in envs:
            logger.debug("Working in env: %s" % environment)
            vpc = v.get_vpc_from_env(env=environment)
            domain = Misc.get_value_from_array_hash(dictlist=vpc.get('Tags'), key="Domain")
            zoneid = r.get_zoneid_from_domain(domain=domain)
            records = r.list_zone_records(zoneid=zoneid)
            for record in records:
                rec = record.pop('ResourceRecords', [])
                values = []
                for rr in rec:
                    values.append(rr['Value'])
                record['Values'] = values
                if 'AliasTarget' in record:
                    aliastarget = record.pop('AliasTarget')
                    record['TTL'] = 'alias'
                    record['Values'] = [aliastarget['DNSName']]
                record['Env'] = environment
                res.append(record)
                logger.debug("Processed record is: %s" % record, )
        return res

    def launch_auto_scaling_group(self, env=None, stack=None, min_size=None, max_size=None, xively_service=None,
                                  requester=None, load_balancer_name=None, health_check=None,
                                  health_check_grace_period=None, availability=None, customer=None):
        a = AutoScaling()
        v = Vpc()
        c = CloudWatch()

        logger.info("Starting creation of auto-scaling group")

        auto_scaling_group_name = a.generate_auto_scaling_group_name(env=env, stack=stack,
                                                                     xively_service=xively_service)
        launch_config_name = a.generate_launch_config_name(env=env, stack=stack, xively_service=xively_service)
        lc_exists = a.check_launch_config_exists(env=env, xively_service=xively_service, stack=stack)
        if lc_exists is False:
            logger.info("Starting to Create Launch Configuration: %s" % launch_config_name)
            a.create_launch_config(launch_config_name=launch_config_name, env=env,
                                   xively_service=xively_service, stack=stack)
        else:
            logger.info("Launch Configuration %s Already Exists" % launch_config_name)

        vpc = v.get_vpc_from_env(env=env)
        subnet_filter = v.get_all_subnets(filters=[{"Name": "tag:Availability", "Values": [availability, ]},
                                                   {"Name": "vpc-id", "Values": [vpc.get('VpcId'), ]}])
        vpc_zones = ""
        for s in subnet_filter:
            vpc_zones += str(s['SubnetId'])
            vpc_zones += str(",")

        tags = [
            {"ResourceId": auto_scaling_group_name, "ResourceType": "auto-scaling-group", "PropagateAtLaunch": False,
             "Key": "Name", "Value": auto_scaling_group_name},
            {"ResourceId": auto_scaling_group_name, "ResourceType": "auto-scaling-group", "PropagateAtLaunch": True,
             "Key": "Requester", "Value": requester},
            {"ResourceId": auto_scaling_group_name, "ResourceType": "auto-scaling-group", "PropagateAtLaunch": True,
             "Key": "Puppet_role", "Value": stack},
            {"ResourceId": auto_scaling_group_name, "ResourceType": "auto-scaling-group", "PropagateAtLaunch": True,
             "Key": "Xively_service", "Value": xively_service},
            {"ResourceId": auto_scaling_group_name, "ResourceType": "auto-scaling-group", "PropagateAtLaunch": True,
             "Key": "Environment", "Value": env},
            {"ResourceId": auto_scaling_group_name, "ResourceType": "auto-scaling-group", "PropagateAtLaunch": True,
             "Key": "Customer", "Value": customer}]

        asg = []
        asg.append(auto_scaling_group_name)
        asg_exists = a.check_auto_scaling_group_exists(auto_scaling_group_name=asg)
        if asg_exists is False:
            logger.info("Starting to Create Auto Scaling Group: %s" % launch_config_name)
            a.run_auto_scaling_group(auto_scaling_group_name=auto_scaling_group_name, min_size=min_size,
                                     max_size=max_size,
                                     launch_config_name=launch_config_name, load_balancer_name=load_balancer_name,
                                     health_check=health_check, health_check_grace_period=health_check_grace_period,
                                     vpc_zones=vpc_zones, tags=tags)
        # resp = a.get_status_auto_scaling_group(auto_scaling_group_name=auto_scaling_group_name)
        #            logger.info(resp)
        else:
            logger.info("Auto Scaling Group %s Already Exists" % launch_config_name)

        a.create_scaling_policy(env=env, stack=stack, xively_service=xively_service)
        c.create_alarm_for_auto_scaling_group(env=env, stack=stack, xively_service=xively_service)

    def get_vpcid_from_env(self, env=None):
        v = Vpc()
        vpc = v.get_vpc_from_env(env=env)
        return vpc.get('VpcId')

    def terminate_instance(self, dryrun=None, instanceids=None):
        e = Ec2()
        ret = e.terminate_instance(dryrun=dryrun, instanceids=instanceids)
        return ret

    def list_iam_users(self):
        i = Iam()
        ret = i.list_users()
        return ret

    def list_iam_groups(self):
        i = Iam()
        ret = i.list_groups()
        return ret

    def list_user_groups(self, username):
        i = Iam()
        ret = i.list_user_groups(username=username)
        return ret

    def list_s3_buckets(self, extended):
        s = S3()
        ret = s.list_buckets()
        # if extended:
        # for bucket in ret:
        # bucket.update(s.get_bucket_acl(bucket=bucket['Name']))
        return ret

    def info_s3_bucket(self, name, choice):
        ret = []
        s = S3()
        region = s.get_bucket_location(name=name)
        s = S3(region=region)
        if choice == "acl":
            acl = s.get_bucket_acl(name=name)
            owner = {'Owner_Displayname': acl['Owner']['DisplayName'], 'Owner_ID': acl['Owner']['ID']}
            for grant in acl['Grants']:
                info = {'Permission': grant['Permission']}
                info.update(owner)
                for key in ['DisplayName', 'EmailAddress', 'ID', 'Type', 'URI']:
                    if key in grant['Grantee']:
                        value = grant['Grantee'][key]
                    else:
                        value = ""
                    info.update({key: value})
                ret.append(info)
        elif choice == 'lifecycle':
            lifecycle = s.get_bucket_lifecycle(name=name)
            print lifecycle
            # FIXME need to test and configure
        elif choice == 'region':
            ret.append({'Region': region})
        elif choice == 'logging':
            logging = s.get_bucket_logging(name=name)
            print logging
            # FIXME need to test and configure
        elif choice == 'policy':
            policy = s.get_bucket_policy(name=name)
            print policy
            # FIXME need to test and configure
        elif choice == 'replication':
            replication = s.get_bucket_replication(name=name)
            print replication
            # FIXME need to test and configure
        elif choice == 'tagging':
            tags = s.get_bucket_tagging(name=name)
            ret = tags
        else:
            logger.error("Unknown choice request: %s" % choice, )
        return ret

    def list_user_credentials(self):
        i = Iam()
        users = i.list_users()
        ret = []
        for user in users:
            creds = i.list_user_credentials(username=user['UserName'])
            for cred in creds:
                last_used = i.get_access_key_last_used(access_key=cred['AccessKeyId'])
                cred.update(last_used)
                ret.append(cred)
        return ret

    def create_user_credentials(self, username, dryrun):
        i = Iam()
        creds = i.create_user_credentials(username=username, dryrun=dryrun)
        return [creds]


def ssl_ports_in_elb(elb=None):
    ports = []
    for listener in elb['ListenerDescriptions']:
        if 'SSLCertificateId' in listener['Listener']:
            logger.debug("Found SSL port in elb")
            ports.append(listener['Listener']['LoadBalancerPort'])
        else:
            logger.debug("This is not an SSL listener")
    return ports
