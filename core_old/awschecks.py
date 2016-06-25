import os
import re

import yaml

from misc.Logger import logger
from misc import Misc
from wrapper.ec2 import Ec2
from wrapper.vpc import Vpc
from wrapper.elb import Elb
from wrapper.iam import Iam
from wrapper.rds import Rds
from wrapper.s3 import S3
from wrapper.route53 import Route53
from misc.XML import XML
from core.base import base
from core.generate import generate
import urllib2, json
from misc.Hipchat import hc


class awschecks(base):
    def __init__(self, region="us-east-1"):
        logger.debug("Starting awschecks")
        try:
            config_file = open("%s/etc/aws.conf" % (os.environ['KERRIGAN_ROOT'],), 'r')
            self.yaml = yaml.load(config_file)
        except IOError as e:
            logger.error("aws.conf I/O error({0}): {1}".format(e.errno, e.strerror))
        self.owner = self.yaml['owner']
        self.region = region

    # FIXME all checks are broken currently because of switch to boto3
    def check_security_groups(self, create=False, modify=False, remove=False):
        logger.info("Checking if tags are present")
        e = Ec2()
        security_groups = e.get_security_groups()
        tags = Misc.get_yaml_tags_for_sub(sub='security_group')
        xml = XML(name="SGtags", feature="security_group")
        for sg in security_groups:
            all_tags = tags.keys()
            Misc.check_tags(resource=sg, goldentags=all_tags, modify=modify, xml=xml)
        xml.output()
        xml = XML(name="SGTagsNotEmpty", feature="security_group")
        for sg in security_groups:
            mandatory = Misc.mandatory_tags(tags=tags)
            Misc.tags_not_empty(resource=sg, xml=xml, tags=mandatory)
        xml.output()

    def check_amis(self, create=None, modify=None, remove=False):
        e = Ec2()
        amis = e.get_images()
        tags = Misc.get_yaml_tags_for_sub(sub='ami')
        xml = XML(name="AMItags", feature="ami")
        for ami in amis:
            all_tags = tags.keys()
            Misc.check_tags(resource=ami, goldentags=all_tags, modify=modify, xml=xml)
        xml.output()
        xml = XML(name="AMITagsNotEmpty", feature="ami")
        for ami in amis:
            mandatory = Misc.mandatory_tags(tags=tags)
            Misc.tags_not_empty(resource=ami, xml=xml, tags=mandatory)
        xml.output()

    def check_subnets(self, create=False, modify=False, remove=False):
        v = Vpc()
        subnets = v.get_all_subnets()
        tags = Misc.get_yaml_tags_for_sub(sub='subnet')
        xml = XML(name="Subnettags", feature="subnet")
        for subnet in subnets:
            all_tags = tags.keys()
            Misc.check_tags(resource=subnet, goldentags=all_tags, modify=modify, xml=xml)
        xml.output()
        xml = XML(name="SubnetTagsNotEmpty", feature="subnet")
        for subnet in subnets:
            mandatory = Misc.mandatory_tags(tags=tags)
            Misc.tags_not_empty(resource=subnet, xml=xml, tags=mandatory)
        xml.output()

    def check_vpcs(self, create=False, modify=False, remove=False):
        v = Vpc()
        vpcs = v.get_all_vpcs()
        tags = Misc.get_yaml_tags_for_sub(sub='vpc')
        xml = XML(name="VPCtags", feature="vpc")
        for vpc in vpcs:
            all_tags = tags.keys()
            Misc.check_tags(resource=vpc, goldentags=all_tags, modify=modify, xml=xml)
        xml.output()
        xml = XML(name="VPCTagsNotEmpty", feature="vpc")
        for vpc in vpcs:
            mandatory = Misc.mandatory_tags(tags=tags)
            Misc.tags_not_empty(resource=vpc, xml=xml, tags=mandatory)
        xml.output()

    def check_instances(self, create=False, modify=False, remove=False):
        e = Ec2()
        instances = e.get_all_instances()
        tags = Misc.get_yaml_tags_for_sub(sub='instance')
        xml = XML(name="EC2instancetags", feature="ec2")
        for instance in instances:
            all_tags = tags.keys()
            Misc.check_tags(resource=instance, goldentags=all_tags, modify=modify, xml=xml)
        xml.output()
        xml = XML(name="EC2TagsNotEmpty", feature="ec2")
        for instance in instances:
            mandatory = Misc.mandatory_tags(tags=tags)
            Misc.tags_not_empty(resource=instance, xml=xml, tags=mandatory)
        xml.output()

    def compare_elb(self, env=None):
        v = Vpc()
        elb = Elb()
        envs = super(awschecks, self).get_needed_envs(env=env)
        yaml = Misc.get_aws_yaml(yaml_file="elb")
        elbs = elb.sort_elbs_to_vpc()
        for env in envs:
            logger.info("Investigating env %s" % env, )
            vpc = v.get_vpc_from_env(env=env)
            if vpc.get('VpcId') in elbs:
                env_elbs = elbs[vpc.get('VpcId')]
            else:
                env_elbs = []
            for golden_elb in yaml:
                for facing in yaml[golden_elb]:
                    logger.info("Checking %s facing %s" % (golden_elb, facing))
                    if env not in yaml[golden_elb][facing]['env']:
                        logger.info("Elb %s should not be provisioned to environment %s" % (golden_elb, env))
                        continue
                    listener = generate_listener(env=env, ssl=yaml[golden_elb][facing]['ssl'],
                                                 listener=yaml[golden_elb][facing]['listener'])
                    yaml_tags = yaml[golden_elb][facing]['tags']
                    gen_tags = []
                    sg_name = yaml[golden_elb][facing]['sg']
                    yaml_health = yaml[golden_elb][facing]['healthcheck']
                    for y in yaml_tags:
                        gen_tags.append({'Key': y, 'Value': yaml_tags[y]})
                    [lb, env_elbs] = find_elb(elb=elb.generate_elb_name(stack=golden_elb, env=env, facing=facing),
                                              facing=facing, elbs=env_elbs)
                    if not lb:
                        logger.info("We need to create the elb")
                        lb_name = elb.create_elb(scheme=facing, listeners=listener, env=env, tags=gen_tags,
                                                 name=golden_elb,
                                                 sg_name=sg_name)
                        elb.configure_health_check(name=lb_name, healthcheck=yaml_health)
                        elb.modify_lb_atrribs(name=lb_name, attribs={'CrossZoneLoadBalancing': {'Enabled': True}})
                    else:
                        logger.debug("We need to check settings of elb")
                        comapre_elb(elb=lb, scheme=facing, listeners=listener, env=env, tags=gen_tags, sg_name=sg_name)
                        # Health check
                        healthcheck = lb.get('HealthCheck')
                        if compare_elb_healthcheck(yaml_healthcheck=yaml_health, elb_healthcheck=healthcheck):
                            logger.debug("Both healthchecks are the same.")
                        else:
                            elb.configure_health_check(name=lb.get('LoadBalancerName'), healthcheck=yaml_health)
                        # Cross Zone loadbalancing
                        attribs = elb.describe_lb_attribs(name=lb.get('LoadBalancerName'))
                        if attribs['CrossZoneLoadBalancing']['Enabled'] is False:
                            logger.debug("Elb needs to have CrossZoneLoadBalancing enabled")
                            elb.modify_lb_atrribs(name=lb.get('LoadBalancerName'),
                                                  attribs={'CrossZoneLoadBalancing': {'Enabled': True}})
                        else:
                            logger.debug("Elb has cross zone loadbalancing enabled")
            for e in env_elbs:
                logger.error("Elb is not documented in yaml %s" % e.get('LoadBalancerName'), )

    def compare_securitygroups(self, env=None, dryrun=False):
        ec2 = Ec2()
        v = Vpc()
        envs = super(awschecks, self).get_needed_envs(env=env)
        for env in envs:
            yaml = Misc.get_aws_yaml(yaml_file="sg_groups")
            logger.info("Investigating env %s" % env, )
            vpc = v.get_vpc_from_env(env=env)
            vpc_avail = Misc.get_value_from_array_hash(dictlist=vpc['Tags'], key="Availability")
            logger.debug("Avail is: %s" % vpc_avail, )
            sgs = ec2.get_security_groups(filters=[{'Name': 'vpc-id', 'Values': [vpc.get('VpcId')]}])
            goldens = yaml['golden']
            if env in yaml:
                logger.info("Env has specific security rules: %s" % env, )
                env_sg_rule = yaml[env]
            else:
                env_sg_rule = None
            # FIXME move options to dict for better management
            # Os block
            do_golden_element_for_sg(element_name="OS", tag_name="Os", sgs=sgs, vpc_avail=vpc_avail,
                                     env_sg_rule=env_sg_rule, goldens=goldens, ec2=ec2, env=env,
                                     vpc_id=vpc.get('VpcId'), dryrun=dryrun)
            # PR block
            do_golden_element_for_sg(element_name="PR", tag_name="Puppet_role", sgs=sgs, vpc_avail=vpc_avail,
                                     env_sg_rule=env_sg_rule, goldens=goldens, ec2=ec2, env=env,
                                     vpc_id=vpc.get('VpcId'), dryrun=dryrun)
            # XS Block
            do_golden_element_for_sg(element_name="XS", tag_name="Xively_service", sgs=sgs, vpc_avail=vpc_avail,
                                     env_sg_rule=env_sg_rule, goldens=goldens, ec2=ec2, env=env,
                                     vpc_id=vpc.get('VpcId'), dryrun=dryrun)
            # ELB Block
            do_golden_element_for_sg(element_name="ELB", tag_name="ELB", sgs=sgs, vpc_avail=vpc_avail,
                                     env_sg_rule=env_sg_rule, goldens=goldens, ec2=ec2, env=env,
                                     vpc_id=vpc.get('VpcId'), dryrun=dryrun)
            # RDS Block
            do_golden_element_for_sg(element_name="RDS", tag_name="RDS", sgs=sgs, vpc_avail=vpc_avail,
                                     env_sg_rule=env_sg_rule, goldens=goldens, ec2=ec2, env=env,
                                     vpc_id=vpc.get('VpcId'), dryrun=dryrun)
            # Remove the default security group, which cannot be deleted
            for sg in sgs:
                # Remaining Sgs
                if sg.get('GroupName') == "default":
                    logger.info("default security group, leave it alone")
                    continue
                logger.error("Sg is not in standards, possible delete: %s" % sg.get('GroupId'), )

    def compare_certs(self, env=None):
        v = Vpc()
        iam = Iam()
        envs = super(awschecks, self).get_needed_envs(env=env)
        logger.debug("Investigated envs are: %s" % envs, )
        certs = iam.get_server_certs()
        files = Misc.list_cert_files()
        for e in envs:
            vpc = v.get_vpc_from_env(env=e)
            domain = Misc.get_value_from_array_hash(dictlist=vpc.get('Tags'), key="Domain")
            logger.info("Env with domain is: %s, %s" % (e, domain))
            star_domain = "star." + domain
            [cert, certs] = find_server_cert(certs=certs, domain=star_domain)
            if cert is None:
                logger.error("There is no Certificate for %s in aws" % star_domain, )
            else:
                ext_info = iam.get_server_cert(name=star_domain)
                cert_body = Misc.get_cert_body(name=star_domain)
                if cert_body:
                    if ext_info.get('CertificateBody') == cert_body:
                        logger.info("Local certificate body and remote is same")
                    else:
                        logger.error("Certificate Body does not match local copy %s" % star_domain, )
            if star_domain in files:
                logger.debug("Domain has cert in local store")
                files.remove(star_domain)
            else:
                logger.error("Certificate has no local copy: %s" % star_domain, )
        for file in files:
            if file.startswith('old.'):
                logger.warning("This is an old certificate, which should be deleted")
                continue
            logger.debug("These files ave no active environment")
            logger.error("Certificate %s has no environment in AWS" % file, )
        for c in certs:
            logger.debug("These aws certs have no local copy")
            logger.error("AWS certificate is not in local store: %s" % c.get('ServerCertificateName'))

    def compare_route53(self, env=None, dryrun=None):
        envs = super(awschecks, self).get_needed_envs(env=env)
        logger.debug("Investigated envs are: %s" % envs, )
        g = generate()
        r = Route53()
        e = Elb()
        ec2 = Ec2()
        v = Vpc()
        envs_with_domains = g.envs_with_domains()
        process = {}
        for env in envs:
            process[env] = envs_with_domains[env]
        for env in process:
            for domain in process[env]:
                logger.info("Iterating env %s domain %s" % (env, domain))
                domain_end = [".com", ".us"]
                if domain.endswith(tuple(domain_end)):
                    external = True
                    yaml_elb = get_elb_yaml_dns_entries(facing="internet-facing", env=env)
                    yaml_rds = None
                elif domain.endswith(".local"):
                    external = False
                    yaml_elb = get_elb_yaml_dns_entries(facing="internal", env=env)
                    yaml_rds = get_rds_yaml_dns_entries(env=env)
                zoneid = r.get_zoneid_from_domain(domain=domain)
                records = r.list_zone_records(zoneid=zoneid)
                active_records = {}
                for elb in yaml_elb:
                    lb = e.get_elb_from_env_and_tag(env=env, tags=yaml_elb[elb]['tags'],
                                                    facing=yaml_elb[elb]['facing'])
                    if len(lb) == 1:
                        lb = lb[0]
                        yaml_elb[elb]['elb'] = lb
                    else:
                        logger.error("ELB count in env has problems: env %s, elb: %s" % (env, elb))
                        continue
                for record in records:
                    if record['Name'].endswith('.'):
                        # Cutting down last tailoring .
                        record['Name'] = Misc.remove_last_n_char(string=record['Name'])
                    tmp_name = record['Name'][:-len(domain)]
                    if tmp_name != '':
                        if tmp_name.endswith('.'):
                            tmp_name = Misc.remove_last_n_char(string=tmp_name)
                        if 'AliasTarget' in record:
                            active_records[tmp_name] = parse_alias_record(record=record)
                        else:
                            active_records[tmp_name] = parse_normal_record(record=record)
                # Compare to needed env variables
                # ELB
                [create, update, active_records] = compare_elb_records(yaml_records=yaml_elb,
                                                                       active_records=active_records, external=external)
                add_elb_record(records=create, domain=domain, zoneid=zoneid, external=external, dryrun=dryrun)
                update_elb_record(records=update, domain=domain, zoneid=zoneid, external=external, dryrun=dryrun)
                # RDS
                if yaml_rds is not None:
                    [create, active_records] = compare_rds_records(yaml_records=yaml_rds, active_records=active_records,
                                                                   env=env)
                    add_rds_record(records=create, zoneid=zoneid, env=env, domain=domain, dryrun=dryrun)
                # Broker
                if external:
                    active_records = self.check_gws_in_env(env=env, zoneid=zoneid, domain=domain, dryrun=dryrun,
                                                           active_records=active_records)
                # Puppet
                vpc = v.get_vpc_from_env(env=env)
                puppet_ec2 = ec2.get_all_instances(filters=[{'Name': 'vpc-id', 'Values': [vpc.get('VpcId')]},
                                                            {'Name': 'tag:Puppet_role', 'Values': ['puppetmasterv2']},
                                                            {'Name': 'tag:Requester', 'Values': ['devops']}])
                puppet_ec2 = puppet_ec2[0]
                [create, update, active_records] = compare_puppet_records(active_records=active_records,
                                                                          external=external, puppet_ec2=puppet_ec2)
                if create:
                    add_puppet_record(ip=create, domain=domain, zoneid=zoneid, dryrun=dryrun)
                if update:
                    update_puppet_record(domain=domain, zoneid=zoneid, record=update, dryrun=dryrun)
                # opscenter
                [create, update, active_records] = compare_opscenter_records(active_records=active_records, env=env)
                if create:
                    add_opscenter_record(records=create, domain=domain, zoneid=zoneid, dryrun=dryrun)
                # ETC
                [create, update, active_records] = compare_custom_records(active_records=active_records, env=env)
                if active_records is not None:
                    for record in active_records:
                        logger.error("This record is not in our automatisation %s.%s" % (record, domain))

    def check_gws_in_env(self, env=None, zoneid=None, domain=None, active_records=None, dryrun=None):
        e = Ec2()
        r = Route53()
        v = Vpc()
        vpc = v.get_vpc_from_env(env=env)
        logger.info("Working on GW Env: %s" % (env,))
        instances = e.get_all_instances(filters=[{'Name': 'tag:Puppet_role', 'Values': ['gateway']},
                                                 {'Name': 'instance-state-name', 'Values': ["running"]},
                                                 {'Name': 'vpc-id', 'Values': [vpc.get('VpcId')]}])
        ips = {'active': [], 'deactive': []}
        hostname_to_ip = {}
        for i in instances:
            pubip = i.get('PublicIpAddress')
            privip = i.get('PrivateIpAddress')
            hostname = Misc.get_value_from_array_hash(dictlist=i.get('Tags'), key='Name')
            logger.info("Public ip is: %s private ip is: %s" % (pubip, privip))
            url = "https://%s/status" % (privip,)
            logger.debug("Status URL is: %s" % (url,))
            try:
                response = urllib2.urlopen(url, timeout=10)
            except urllib2.URLError, e:
                logger.error("Gateway timed out. Error: %s" % e, )
                continue
            data = json.loads(response.read())
            # FIXME are connections drained down.
            if data["gw_inactive"].lower() == "false":
                logger.info("Gateway is active")
                ips['active'].append(pubip)
                if env == 'prod':
                    hostname_to_ip[hostname + ".broker"] = pubip
                else:
                    hostname_to_ip[hostname] = pubip
            elif data["gw_inactive"].lower() == "true":
                logger.info("Gateway is deactivated")
                ips['deactive'].append(pubip)
            else:
                logger.error("Gateway is in unkown state")
        r.manage_gw_for_route53(ips=ips, zoneid=zoneid, domain=domain, dryrun=dryrun)
        r.manage_single_gw_record(machines=hostname_to_ip, zoneid=zoneid, domain=domain, env=env, dryrun=dryrun)
        if active_records:
            # FIXME manage customer gw entries somehow
            if "broker" in active_records:
                active_records.pop("broker")
            for machine in hostname_to_ip:
                if machine in active_records:
                    logger.info("Removing machine from active records %s" % machine, )
                    active_records.pop(machine)
            ret = {}
            for record in active_records:
                if record.endswith(".broker"):
                    logger.info("Entry is a customer record, just removing")
                    continue
                # FIXME just a quick fix for now here. Need to add customer entries later
                if record.endswith(".timeseries"):
                    logger.info("Entry is a customer record, just removing")
                    continue
                ret[record] = active_records[record]
            active_records = ret
        return active_records

    def sync_instances_to_elbs(self, env=None, dryrun=None):
        envs = super(awschecks, self).get_needed_envs(env=env)
        ec2 = Ec2()
        e = Elb()
        v = Vpc()
        elbs = e.sort_elbs_to_vpc()
        for env in envs:
            vpc = v.get_vpc_from_env(env=env)
            if vpc.get('VpcId') in elbs:
                env_elbs = elbs[vpc.get('VpcId')]
            else:
                env_elbs = []
            for elb in env_elbs:
                filters = [{'Name': 'vpc-id', 'Values': [vpc.get('VpcId')]}]
                xs_value = Misc.get_value_from_array_hash(dictlist=elb['Tags'], key="Xively_service")
                pr_value = Misc.get_value_from_array_hash(dictlist=elb['Tags'], key="Puppet_role")
                if pr_value is None:
                    logger.error("Elb has no Puppet_role value %s" % (elb.get('LoadBalancerName'),))
                    continue
                filters.append({'Name': "tag:Puppet_role", 'Values': [pr_value]})
                filters.append({'Name': "tag:Xively_service", 'Values': [xs_value]})
                if xs_value is None and pr_value is None:
                    logger.error("Issues with ELB %s, both tags are empty" % elb.get('LoadBalancerName'))
                    continue
                instances = ec2.get_all_instances(filters=filters)
                instance_ids = []
                for instance in instances:
                    if instance.get('State').get('Name') == "running":
                        instance_ids.append(instance.get('InstanceId'))
                for i in instance_ids:
                    if is_instance_id_in_elb(instance_id=i, elb_instances=elb.get('Instances')):
                        logger.info("Instance id %s is member of elb %s" % (i, elb.get('LoadBalancerName')))
                    else:
                        e.add_instance_to_elb(dryrun=dryrun, name=elb.get('LoadBalancerName'),
                                              instances=[{'InstanceId': i}])

    def is_env_public(self, env=None):
        v = Vpc()
        vpc = v.get_vpc_from_env(env=env)
        avail = Misc.get_value_from_array_hash(dictlist=vpc['Tags'], key='Availability')
        if Misc.str2bool(avail):
            return True
        else:
            return False

    def compare_iam(self, dryrun, env=None):
        envs = super(awschecks, self).get_needed_envs(env=env)
        i = Iam()
        policies = i.list_policies()
        users = i.list_users()
        for env in envs:
            yaml = Misc.get_aws_yaml(yaml_file="iam")
            hc.normal_message("Running iam automation in %s environment. Dryrun: %s " % (env, dryrun))
            logger.info("Investigating env %s" % env, )
            for service in yaml:
                if env not in yaml[service]['env']:
                    logger.info("Iam policy %s should not be provisioned to environment %s" % (service, env))
                    continue
                final_policies = []
                for num in [1, 2]:
                    service_arn_name = "%s-%s-%s" % (env, service, num)
                    service_arn = Misc.generate_arn(region="", service="iam",
                                                    resourcetype="policy/%s" % service_arn_name, )
                    policy = i.get_policy(arn=service_arn)
                    formated_statement = Misc.format_data(data=yaml[service]["statement_%s" % num],
                                                          variables={'region': self.region, 'account': self.owner,
                                                                     'env': env})
                    if formated_statement is None:
                        logger.info("No Statement given, skipping")
                        continue
                    if policy is None:
                        # Need to create
                        hc.change_notification("Going to create iam role %s" % (service_arn_name,))
                        created_policy = i.create_policy(statement=formated_statement, name=service_arn_name,
                                                         description="Iam policy for %s" % (service_arn_name,),
                                                         dryrun=dryrun)
                        final_policies.append(created_policy)
                    else:
                        # need to find from all policies
                        final_policies.append(policy)
                        policies = remove_policy(policies=policies, policy=policy)
                        document = i.get_policy_version(arn=policy['Arn'], version=policy['DefaultVersionId'])
                        document = compare_iam(policy=policy, yaml=formated_statement, document=document)
                        if document:
                            logger.error(
                                "IAM policy has extra/missing statements that need to be managed: " + str(document))
                            hc.anomaly_detected("Iam policy %s has extra statements, which need to be removed: %s" % (
                                service_arn_name, str(document)))
                            i.create_policy_version(arn=policy['Arn'], statement=formated_statement, dryrun=dryrun)
                        versions = i.get_policy_versions(arn=policy['Arn'])
                        if len(versions) > 3:
                            logger.warning("More than 3 policy versions. Need to remove older ones")
                            hc.change_notification(
                                "Iam policy %s has more than 3 versions. Going to remove old. No impact for operation." % (
                                    service_arn_name,))
                            i.remove_older_policy_versions(arn=policy['Arn'], dryrun=dryrun)
                # Check users
                username = "%s-%s" % (env, service)
                [user, users] = find_user(users=users, username=username)
                if len(user) < 1:
                    logger.debug("Need to create user")
                    hc.change_notification("Iam automation will create user: %s" % (username,))
                    user = i.create_user(username=username, dryrun=dryrun)
                    # credentials = i.create_user_credentials(username=username, dryrun=dryrun)
                    # logger.info("Access key for user %s: %s" % (username, credentials['AccessKey']['AccessKeyId']))
                    # logger.info("Secret key for user %s: %s" % (username, credentials['AccessKey']['SecretAccessKey']))
                    if dryrun:
                        logger.warning(
                            "Since user was not created because of dryrun, further steps cannot be completed")
                        continue
                else:
                    logger.debug("User exists")
                    user = user[0]
                attached_policies = i.get_user_policies(username=username)
                for p in attached_policies:
                    # Need to test if policy should not be attached
                    if any(p['PolicyArn'] != pol['Arn'] for pol in final_policies):
                        hc.change_notification("Going to detach Policy %s from user %s" % (p['PolicyArn'], username))
                        i.detach_policy_from_user(username=username, policyarn=p['PolicyArn'], dryrun=dryrun)
                for p in final_policies:
                    if any(p['Arn'] == pol['PolicyArn'] for pol in attached_policies):
                        logger.debug("Policy attached to user")
                    else:
                        hc.change_notification("Going to attach Policy %s to user %s" % (p['Arn'], username))
                        i.attach_policy_to_user(username=username, policyarn=p['Arn'], dryrun=dryrun)
            hc.change_done("Iam automation run complete in env %s" % (env,))

    def compare_s3(self, env):
        envs = super(awschecks, self).get_needed_envs(env=env)
        s3_yaml = Misc.get_aws_yaml(yaml_file="iam")
        s3 = S3()
        buckets = s3.list_buckets()
        for env in envs:
            logger.info("Investigating env %s" % env, )
            bucket_name = "xively-services-%s" % (env,)
            env_bucket = [b for b in buckets if b['Name'] == bucket_name]
            if not env_bucket:
                location = s3.create_bucket(name=bucket_name)
            for service in s3_yaml:
                if env not in s3_yaml[service]['env']:
                    logger.error("This service %s should not be provisioned to this environment %s" % (service, env))
                    continue
                objects = s3.get_object(bucket_name=bucket_name, key="%s/" % (service,))
                if objects is None:
                    resp = s3.create_folder(bucket_name=bucket_name, key="%s/" % (service,))


def add_elb_record(records=None, domain=None, zoneid=None, external=None, dryrun=None):
    r = Route53()
    for record in records:
        logger.info("Going to create ELB record %s" % record, )
        if 'elb' in records[record]:
            elb = records[record]['elb']
        else:
            # There were multiple elbs with same name
            logger.error("ELB %s has no elb object." % record, )
            continue
        # FIXME this is a workaround... Amazon has not implemented function
        if external:
            alias = {'HostedZoneId': elb.get('CanonicalHostedZoneNameID'),
                     'DNSName': elb.get('DNSName'),
                     'EvaluateTargetHealth': False}
            change = {'Action': 'UPSERT',
                      'ResourceRecordSet': {'Name': "%s.%s." % (record, domain), 'Type': 'A', 'AliasTarget': alias}}
        else:
            change = {'Action': 'UPSERT',
                      'ResourceRecordSet': {'Name': "%s.%s." % (record, domain), 'Type': 'CNAME', 'TTL': 300,
                                            'ResourceRecords': [{'Value': elb.get('DNSName')}]}}
        changebatch = {'Comment': "Change for domain %s" % (elb.get('DNSName'),), 'Changes': [change]}
        r.change_record_for_zoneid(zoneid=zoneid, changebatch=changebatch, dryrun=dryrun)


def update_elb_record(records=None, domain=None, zoneid=None, external=None, dryrun=None):
    r = Route53()
    for record in records:
        logger.info("Going to update ELB record %s" % record, )
        if 'elb' in records[record]:
            elb = records[record]['elb']
        else:
            # There were multiple elbs with same name
            logger.error("ELB %s has no elb object." % record, )
            continue
        delete_rr = []
        for rr in records[record]['dns_rr']:
            delete_rr.append({'Value': rr})
        if records[record]['dns_type'] == "alias":
            dns_type = "A"
        else:
            dns_type = records[record]['dns_type']
        change_delete = {'Action': 'DELETE',
                         'ResourceRecordSet': {'Name': "%s.%s." % (record, domain), 'Type': dns_type,
                                               'ResourceRecords': delete_rr}}
        if 'dns_ttl' in records[record]:
            change_delete['ResourceRecordSet']['TTL'] = records[record]['dns_ttl']
        if external:
            alias = {'HostedZoneId': elb.get('CanonicalHostedZoneNameID'),
                     'DNSName': elb.get('DNSName'),
                     'EvaluateTargetHealth': False}
            change_create = {'Action': 'UPSERT',
                             'ResourceRecordSet': {'Name': "%s.%s." % (record, domain), 'Type': 'A',
                                                   'AliasTarget': alias}}
        else:
            change_create = {'Action': 'CREATE',
                             'ResourceRecordSet': {'Name': "%s.%s." % (record, domain), 'Type': 'CNAME', 'TTL': 300,
                                                   'ResourceRecords': [
                                                       {'Value': elb.get('DNSName')}]}}

        changebatch = {'Comment': "Change for domain %s" % (elb.get('DNSName'),),
                       'Changes': [change_delete, change_create]}
        r.change_record_for_zoneid(zoneid=zoneid, changebatch=changebatch, dryrun=dryrun)


def add_rds_record(records=None, domain=None, zoneid=None, env=None, dryrun=None):
    e = Rds()
    r = Route53()
    v = Vpc()
    vpc = v.get_vpc_from_env(env=env)
    for record in records:
        logger.info("Going to create RDS record %s" % record, )
        rds = e.get_db_instances(
            filters=[{'Name': 'VpcId', 'Values': [vpc.get('VpcId')]}, {'Name': 'tag:Name', 'Values': [record]}])
        if len(rds) == 1:
            rds = rds[0]
        else:
            logger.error("rds count in env has problems: env %s, rds: %s" % (env, record))
            continue
        rds_dns = rds.get('Endpoint').get('Address')
        change = {'Action': 'UPSERT',
                  'ResourceRecordSet': {'Name': "%s.%s." % (record, domain), 'Type': 'CNAME',
                                        'ResourceRecords': [{'Value': rds_dns}], 'TTL': 300}}
        changebatch = {'Comment': "Change for domain %s" % (rds_dns,), 'Changes': [change]}
        r.change_record_for_zoneid(zoneid=zoneid, changebatch=changebatch, dryrun=dryrun)


def add_puppet_record(ip=None, domain=None, zoneid=None, dryrun=None):
    r = Route53()
    change = {'Action': 'UPSERT',
              'ResourceRecordSet': {'Name': "puppet.%s." % (domain,), 'Type': 'A',
                                    'ResourceRecords': [{'Value': ip}], 'TTL': 300}}
    changebatch = {'Comment': "Change for domain puppet.%s" % (domain,), 'Changes': [change]}
    r.change_record_for_zoneid(zoneid=zoneid, changebatch=changebatch, dryrun=dryrun)


def add_opscenter_record(records=None, domain=None, zoneid=None, dryrun=None):
    r = Route53()
    for opscenter in records:
        change = {'Action': 'UPSERT',
                  'ResourceRecordSet': {'Name': "%s.%s" % (opscenter, domain), 'Type': 'A',
                                        'ResourceRecords': [{'Value': records[opscenter]}], 'TTL': 300}}
        changebatch = {'Comment': "Change for domain %s.%s" % (opscenter, domain), 'Changes': [change]}
        r.change_record_for_zoneid(zoneid=zoneid, changebatch=changebatch, dryrun=dryrun)


def update_puppet_record(record=None, zoneid=None, domain=None, dryrun=None):
    r = Route53()
    rr = []
    for val in record['Values']:
        rr.append({'Value': val})
    change_delete = {'Action': 'DELETE',
                     'ResourceRecordSet': {'Name': "puppet.%s." % (domain,), 'Type': record['type'],
                                           'ResourceRecords': rr, 'TTL': record['ttl']}}
    change_create = {'Action': 'CREATE',
                     'ResourceRecordSet': {'Name': "puppet.%s." % (domain,), 'Type': 'A', 'TTL': 300,
                                           'ResourceRecords': [
                                               {'Value': "%s" % record['ip']}]}}

    changebatch = {'Comment': "Change for domain puppet.%s" % (domain,),
                   'Changes': [change_delete, change_create]}
    r.change_record_for_zoneid(zoneid=zoneid, changebatch=changebatch, dryrun=dryrun)


def compare_rds_records(active_records=None, env=None, yaml_records=None):
    create = {}
    r = Rds()
    v = Vpc()
    vpc = v.get_vpc_from_env(env=env)
    for record in yaml_records:
        rds = r.get_db_instances(
            filters=[{'Name': 'VpcId', 'Values': [vpc.get('VpcId')]}, {'Name': 'tag:Name', 'Values': [record]}])
        if len(rds) == 1:
            rds = rds[0]
        else:
            logger.error("RDS count %s not correct %s" % (record, len(rds)))
            continue
        if record in active_records:
            if active_records[record]['Type'] == 'CNAME':
                dns_value = active_records[record]['Values'][0]
                if dns_value == rds.get('Endpoint').get('Address'):
                    logger.info("DNS entry is same for %s" % record, )
                else:
                    logger.info("Dns value not same, need to change %s" % record, )
                    create[record] = yaml_records[record]
            else:
                logger.info("Record is not same type, need to change %s" % record, )
                # FIXME waiting for workaround from support
                # create[record] = yaml_records[record]
            active_records.pop(record)
        else:
            logger.info("Record does not exists in dns %s" % record, )
            create[record] = yaml_records[record]
    return [create, active_records]


# FIXME test if compare subs can be merged
# FIXME test if create and update subs can be merged
def compare_elb_records(yaml_records=None, active_records=None, external=None):
    create = {}
    update = {}
    for elb in yaml_records:
        logger.debug("Working on elb information: %s" % elb, )
        if active_records is not None and elb in active_records:
            if 'elb' not in yaml_records[elb]:
                logger.error("ELB has no object. Possbile multiple objects from it")
                active_records.pop(elb)
                continue
            logger.info("ELB has an active entry in route 53 %s" % elb, )
            if external:
                dns_type = 'alias'
            else:
                dns_type = 'CNAME'
            if active_records[elb]['Type'] == dns_type:
                dns_value = active_records[elb]['Values'][0]
                if dns_value == yaml_records[elb]['elb'].get('DNSName'):
                    logger.debug("Elb %s has correct dns entry" % (elb,))
                else:
                    create[elb] = yaml_records[elb]
            else:
                logger.warning("Elb record is not a resource record, need to convert: %s" % (elb,))
                yaml_records[elb]['dns_type'] = active_records[elb]['Type']
                if 'TTL' in active_records[elb]:
                    yaml_records[elb]['dns_ttl'] = active_records[elb]['TTL']
                yaml_records[elb]['dns_rr'] = active_records[elb]['Values']
                update[elb] = yaml_records[elb]
            active_records.pop(elb)
        else:
            logger.info("Need to create DNS entry %s" % elb, )
            create[elb] = yaml_records[elb]
    return [create, update, active_records]


def compare_puppet_records(active_records=None, external=None, puppet_ec2=None):
    create = None
    update = None
    if external:
        ip = puppet_ec2.get('PublicIpAddress')
    else:
        ip = puppet_ec2.get('PrivateIpAddress')
    if active_records is not None and 'puppet' in active_records:
        if active_records['puppet']['Type'] == 'A':
            dns_value = active_records['puppet']['Values'][0]
            if dns_value == ip:
                logger.debug("Puppet route53 has correct value")
            else:
                create = ip
        else:
            logger.debug("Need to update record type")
            update = {'ip': ip, 'ttl': active_records['puppet']['TTL'], 'type': active_records['puppet']['Type'],
                      'Values': active_records['puppet']['Values']}
        active_records.pop('puppet')
    else:
        create = ip
    return [create, update, active_records]


def get_elb_yaml_dns_entries(facing=None, env=None):
    yaml = Misc.get_aws_yaml(yaml_file="elb")
    ret = {}
    for stack in yaml:
        if facing in yaml[stack]:
            if env not in yaml[stack][facing]['env']:
                logger.debug("This elb should not be used for env")
                continue
            if yaml[stack][facing]['dns'] in ret:
                logger.error("There is already a domain entry: duplicate: %s" % stack, )
            ret[yaml[stack][facing]['dns']] = {'facing': facing, 'tags': yaml[stack][facing]['tags']}
    logger.debug("Yaml dns entries for elbs are: %s" % ret, )
    return ret


def get_rds_yaml_dns_entries(env=None):
    yaml = Misc.get_aws_yaml(yaml_file="rds")
    ret = {}
    for rds in yaml:
        if env in yaml[rds]['envs']:
            ret[rds] = yaml[rds]['dns']
    return ret


def parse_normal_record(record=None):
    ret = {'Values': []}
    for r in record['ResourceRecords']:
        ret['Values'].append(r['Value'])
    ret['Type'] = record['Type']
    ret['TTL'] = record['TTL']
    return ret


def parse_alias_record(record=None):
    ret = {'Values': []}
    ret['Values'] = [record['AliasTarget']['DNSName']]
    ret['Type'] = 'alias'
    return ret


def get_sg_from_list(sgs=None, tag=None, tagValue=None):
    for sg in sgs:
        if 'Tags' in sg:
            v = Misc.get_value_from_array_hash(dictlist=sg['Tags'], key=tag)
            if v == tagValue:
                logger.debug("Sg is the one with the specified value: %s" % sg.get('GroupId'))
                sgs.remove(sg)
                return [sg, sgs]
        else:
            logger.warning("Sg has no tags %s" % sg.get('GroupId'))
    return [None, sgs]


def generate_sg_rules(vpc_avail=None, sg_public=None, golden=None, env_rules=None, env=None):
    if env_rules:
        rules = golden + env_rules
    elif golden:
        rules = golden
    else:
        rules = []
    result = []
    for rule in rules:
        logger.info("Working on rule %s" % rule, )
        v = Misc.str2bool(vpc_avail)
        if not v and not sg_public:
            logger.debug("Rule should not be public, switching to aws scope")
            if rule['cidr'] == 'public':
                rule['cidr'] = 'lmi'
                ipranges = Misc.get_ipranges(type='aws')
                for ip in ipranges:
                    result.append({'cidr': ip, 'protocol': rule['protocol'], 'port': rule['port']})
        else:
            logger.debug("Rule can be public")
        if rule['cidr'] == 'self':
            result.append({'cidr': 'self', 'protocol': rule['protocol'], 'port': rule['port']})
        # elif rule['cidr'] == 'aws':
        #            ret = generate_aws_rulesets(env=env)
        #            for sg in ret:
        #                result.append({'cidr': sg, 'protocol': rule['protocol'], 'port': rule['port']})
        else:
            ipranges = Misc.get_ipranges(type=rule['cidr'])
            for ip in ipranges:
                result.append({'cidr': ip, 'protocol': rule['protocol'], 'port': rule['port']})
    return result


def generate_aws_rulesets(env=None):
    e = Ec2()
    v = Vpc()
    vpc = v.get_vpc_from_env(env=env)
    sgs = e.get_security_groups(
        filters=[{'Name': 'vpc-id', 'Values': [vpc.get('VpcId')]}, {'Name': 'tag:Os', 'Values': ['linux', 'windows']}])
    ret = []
    for sg in sgs:
        ret.append(sg.get('GroupId'))
        ret.append("10.0.0.0/8")
    return ret


def normalize_sg_rules(sg_rules=None):
    result = []
    for rule in sg_rules:
        if len(rule['UserIdGroupPairs']) > 0:
            for group in rule['UserIdGroupPairs']:
                result.append(
                    {'cidr': group.get('GroupId'), 'protocol': rule.get('IpProtocol'), 'port': rule.get('FromPort'),
                     'to_port': rule.get('ToPort')})
        if len(rule['IpRanges']) > 0:
            for ip in rule['IpRanges']:
                result.append(
                    {'cidr': ip.get('CidrIp'), 'protocol': rule.get('IpProtocol'), 'port': rule.get('FromPort'),
                     'to_port': rule.get('ToPort')})
    return result


def compare_sg_rules(real_rules=None, sg_rules=None, sg_id=None):
    auth = []
    deauth = []
    for sg_rule in sg_rules:
        # Compare the needed rules to the currently implemented ones
        [status, real_rules] = find_rule(sg_rule=sg_rule, real_rules=real_rules, sg_id=sg_id)
        if status:
            logger.debug("Found rule in sg %s" % sg_rule, )
        else:
            logger.debug("Need to append rule %s" % sg_rule, )
            if sg_rule['cidr'] == "self":
                sg_rule['cidr'] = sg_id
            auth.append(sg_rule)
    logger.debug("Remaining rules are: %s" % real_rules, )
    for rule in real_rules:
        logger.debug("Need to deauth rule %s" % rule, )
        if rule['cidr'] == "self":
            rule['cidr'] = sg_id
        deauth.append(rule)
    return [auth, deauth]


def find_rule(sg_rule=None, real_rules=None, sg_id=None):
    logger.debug("sg_rule is %s" % sg_rule, )
    for real_rule in real_rules:
        logger.debug("real_rule is %s" % real_rule, )
        if real_rule['protocol'] == sg_rule['protocol']:
            logger.debug("Type is: %s, port: %s" % (type(sg_rule['port']), sg_rule['port']))
            if isinstance(sg_rule['port'], basestring):
                logger.debug("The port was a string, trying regex")
                m = re.search('\d+-\d+', sg_rule['port'])
            else:
                logger.debug("The port was not a string")
                m = False
            if m:
                logger.debug("We have a regex match")
                [fromport, toport] = sg_rule['port'].split('-')
                if real_rule['port'] == int(fromport) and real_rule['to_port'] == int(toport):
                    logger.debug("This is the from-to range port we are searcing for: %s - %s" % (fromport, toport))
                else:
                    logger.debug("This is not the real_rule we are searching for")
                    continue
            else:
                if real_rule['port'] == sg_rule['port']:
                    logger.debug("This is the port we are searching for %s" % sg_rule['port'])
                else:
                    logger.debug("This is not the real_rule we are searching for")
                    continue
            if sg_rule['cidr'] == 'self':
                if real_rule['cidr'] == sg_id:
                    logger.debug("This group loops back to self and is the one we are searching for")
                    real_rules.remove(real_rule)
                    return [True, real_rules]
            if real_rule['cidr'] == sg_rule['cidr']:
                logger.debug("Cidr range matches")
                real_rules.remove(real_rule)
                return [True, real_rules]
    return [False, real_rules]


def do_golden_element_for_sg(element_name=None, tag_name=None, sgs=None, vpc_avail=None, env_sg_rule=None, goldens=None,
                             ec2=None, env=None, vpc_id=None, dryrun=False):
    for element in goldens[element_name]:
        [sg, sgs] = get_sg_from_list(sgs=sgs, tag=tag_name, tagValue=element)
        if env_sg_rule and element_name in env_sg_rule and element in env_sg_rule[element_name]:
            logger.debug("Element has env specific sg settings")
            env_sg = env_sg_rule[element_name][element]['rules']
        else:
            env_sg = []
        if len(env_sg) > 83:
            logger.warning("More than 83 rules in sg. API call will fail")
        else:
            logger.info("Less than 83 rules for sg")
        if goldens[element_name][element]['must_be_public']:
            sg_public = goldens[element_name][element]['must_be_public']
        else:
            sg_public = False
        if sg is None:
            logger.warning("Sg for %s is not present" % (element,))
            sg_rules = generate_sg_rules(vpc_avail=vpc_avail, golden=goldens[element_name][element]['rules'],
                                         env_rules=env_sg, sg_public=sg_public, env=env)
            if dryrun:
                logger.debug("Dryrun was True, need to create sg")
            ec2.create_sg(sg_rules=sg_rules, name=element, tag_name=tag_name, env=env, vpc_id=vpc_id, dryrun=dryrun)
        else:
            sg_rules = generate_sg_rules(vpc_avail=vpc_avail, golden=goldens[element_name][element]['rules'],
                                         env_rules=env_sg, sg_public=sg_public, env=env)
            real_rules = normalize_sg_rules(sg_rules=sg.get('IpPermissions'))
            [auth, deauth] = compare_sg_rules(real_rules=real_rules, sg_rules=sg_rules, sg_id=sg.get('GroupId'))
            logger.debug("Need to authorize for sg %s : %s" % (sg.get('GroupId'), auth))
            logger.debug("Need to revoke for sg %s : %s" % (sg.get('GroupId'), deauth))
            for rule in auth:
                ec2.authorize_sg_rule(sg_id=sg.get('GroupId'), rule=rule, dryrun=dryrun)
            for rule in deauth:
                ec2.deauthorize_sg_rule(sg_id=sg.get('GroupId'), rule=rule, dryrun=dryrun)


def find_elb(elb=None, elbs=None, facing=None):
    if elbs is not None:
        for e in elbs:
            if facing == e.get('Scheme'):
                logger.debug("The load balancer is facing direction we need")
            else:
                logger.debug("Load balancer is facing wrong direction")
                continue
            if elb == e.get('LoadBalancerName'):
                logger.debug("We have found the elb")
                elbs.remove(e)
                return [e, elbs]
    logger.info("Could not find the elb")
    return [None, elbs]


def generate_listener(listener=None, env=None, ssl=None):
    res = []
    i = Iam()
    for l in listener:
        cur = {}
        cur['Protocol'] = l['protocol']
        cur['LoadBalancerPort'] = int(l['load_balancer_port'])
        cur['InstanceProtocol'] = l['instance_protocol']
        cur['InstancePort'] = int(l['instance_port'])
        if ssl:
            cert = i.get_server_cert_for_env(env=env)
            if cert:
                cur['SSLCertificateId'] = cert.get('Arn')
            else:
                logger.error("Could not find certificate for env %s" % env, )
        res.append(cur)
    return res


def comapre_elb(elb=None, scheme=None, listeners=None, env=None, tags=None, sg_name=None):
    v = Vpc()
    ec2 = Ec2()
    vpc = v.get_vpc_from_env(env=env)
    elb_name = elb.get("LoadBalancerName")
    logger.info("Comparing ELB to baseline: %s" % (elb_name,))
    if vpc.get('VpcId') == elb.get('VPCId'):
        logger.info("ELB in correct environment")
    else:
        logger.error("ELB in not correct environment %s" % elb_name, )
    if elb.get('Scheme') == scheme:
        logger.info("Scheme is same")
    else:
        logger.error("Scheme is not same for ELB %s" % elb_name, )
    if len(elb.get('SecurityGroups')) == 1:
        logger.info("Security group count is correct")
        sg = elb.get('SecurityGroups')[0]
        sg = ec2.get_security_groups(groupids=[sg])[0]
        real_sg_name = Misc.get_value_from_array_hash(dictlist=sg.get('Tags'), key='Name')
        t = sg_name + "_" + env
        if real_sg_name == t:
            logger.info("Yaml sg_name and current one is same")
        else:
            logger.error("ELB %s security group is not correct: current %s, needs %s" % (elb_name, real_sg_name, t))
    else:
        logger.error(
            "Security group count is not good for elb %s count: %s" % (elb_name, len(elb.get('SecurityGroups'))))
    if len(elb.get('ListenerDescriptions')) == len(listeners):
        logger.info("Listener length is same")
        compare_elb_listeners(elb_listener=elb.get('ListenerDescriptions'), elb_name=elb_name, yaml_listener=listeners)
    else:
        logger.error("Listener count not good %s" % elb_name, )
    if elb.get('Tags'):
        for tag in tags:
            key = tag['Key']
            elb_value = Misc.get_value_from_array_hash(dictlist=elb.get('Tags'), key=key)
            if elb_value == tag['Value']:
                logger.debug("Tag value same as yaml")
            else:
                logger.error("Tag value different: elb: %s, key: %s, value_is: %s, value_should: %s" % (
                    elb_name, key, elb_value, tag['Value']))
    else:
        logger.error("ELB has no tags: %s" % elb_name, )


def compare_opscenter_records(env=None, active_records=None):
    e = Ec2()
    create = []
    update = []
    # FIXME validate ttl and record type
    opscenters = e.get_all_instances(
        filters=[{'Name': 'tag:Environment', 'Values': [env]}, {'Name': 'tag:Puppet_role', 'Values': ['opscenter']}])
    for opscenter in opscenters:
        xively_service = Misc.get_value_from_array_hash(dictlist=opscenter.get('Tags'), key="Xively_service")
        full_name = 'opscenter-' + xively_service
        if full_name in active_records:
            logger.debug("Opscenter for %s in dns" % xively_service, )
            if set([opscenter.get('PublicIpAddress')]) == set(active_records[full_name]['Values']):
                logger.info("Opscenter %s has correct value" % full_name, )
            else:
                logger.warning("Need to update Opscenter IP")
                create.append({full_name: opscenter.get('PublicIpAddress')})
            active_records.pop(full_name)
        else:
            create.append({full_name: opscenter.get('PublicIpAddress')})
    return [create, update, active_records]


def compare_custom_records(env=None, active_records=None):
    yaml = Misc.get_aws_yaml('route53')
    records = {}
    create = []
    update = []
    if env in yaml:
        records = yaml[env]
    for key in records:
        if key in active_records:
            # FIXME do some validation here, not just remove entry
            active_records.pop(key)
    return [create, update, active_records]


def compare_elb_listeners(elb_listener=None, yaml_listener=None, elb_name=None):
    # We are doing assumption that there is 1 listener and 1 rule in yaml file, if multiple is added
    # we need to correct this sub
    for elb_l in elb_listener:
        l = elb_l['Listener']
        yaml_l = yaml_listener.pop()
        for l_key in l.keys():
            if l_key in yaml_l:
                if ((isinstance(l[l_key], basestring) and (l[l_key].lower() == yaml_l[l_key].lower())) or (
                            l[l_key] == yaml_l[l_key])):
                    logger.info("ELB %s listener key %s is same" % (elb_name, l_key), )
                else:
                    logger.error("ELB %s listener is deferent: key :%s value: %s, should_be: %s" % (
                        elb_name, l_key, l[l_key], yaml_l[l_key]))
            else:
                if l_key == "SSLCertificateId":
                    logger.error(
                        "The two protocols are not matching, thats why certificateID is missing in elb %s" % elb_name, )
                    continue
                logger.warning("Unhandled Key in elb %s listener %s" % (elb_name, l_key))


def find_server_cert(certs=None, domain=None):
    for cert in certs:
        if cert.get('ServerCertificateName') == domain:
            logger.debug("This is the cert we are searching for: %s" % cert, )
            certs.remove(cert)
            return [cert, certs]
        else:
            logger.debug("This is not the cert we are searching for: %s" % cert.get('ServerCertificateName'), )
    return [None, certs]


def compare_elb_healthcheck(yaml_healthcheck=None, elb_healthcheck=None):
    for key in elb_healthcheck.keys():
        if yaml_healthcheck[key] == elb_healthcheck[key]:
            logger.debug("Key %s in healthcheck is same" % key)
        else:
            return False
    return True


def is_instance_id_in_elb(instance_id=None, elb_instances=None):
    for i in elb_instances:
        if i['InstanceId'] == instance_id:
            return True
    return False


def remove_policy(policies, policy):
    index = [i for i, _ in enumerate(policies) if _['PolicyName'] == policy['PolicyName']][0]
    policies.pop(index)
    return policies


def compare_iam(policy, yaml, document):
    document_statements = document['Document']['Statement']
    for st in yaml:
        [found, document_statements] = find_statement(statements=document_statements, statement=st)
        if found:
            logger.info("Removed from policy list")
        else:
            logger.error("Policy should exist, but not found")
            # We just return true that we need to create a new version
            return st
    return document_statements


def find_statement(statements, statement):
    for st in statements:
        if st == statement:
            new_list = [_ for i, _ in enumerate(statements) if _ != statement]
            return [True, new_list]
    return [False, statements]


def find_user(users, username):
    user = [i for i in users if i['UserName'] == username]
    users = [i for i in users if i['UserName'] != username]
    return [user, users]
