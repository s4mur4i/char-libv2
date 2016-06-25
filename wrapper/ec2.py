import operator
from misc.Logger import logger
from misc import Misc
from wrapper.wrapper_base import wrapper_base


class Ec2(wrapper_base):
    def __init__(self, session):
        '''
        This function creates the initial client and resource objects
        :param session: a boto3 session object for connecting to aws
        :return: a wrapper.Ec2 object for running wrapper commands
        '''
        logger.debug("Starting ec2 wrapper")
        self.ec2_client = session.client(service_name="ec2")
        self.ec2_resource = session.resource(service_name="ec2")

    def information_ec2_instances(self, filters):
        '''
        This function is a wrapper around the describe_instances boto3 call.
        Filters can be referenced from: http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_instances
        :param filters: If requested filters that should be used
        :type filters: array of hashes
        :return: an array of EC2.Instance objects
        :rtype: array
        '''
        if filters:
            instances = self.ec2_client.describe_instances(Filters=filters)
        else:
            instances = self.ec2_client.describe_instances()
        super(Ec2, self).query_information(query=instances)
        i = []
        if len(instances['Reservations']) > 0:
            for res in instances['Reservations']:
                for instance in res['Instances']:
                    i.append(instance)
        logger.debug("Instances are: %s" % (i,))
        return i

    def get_ami_stacks(self, account_id):
        '''
        This function returns all active ami Puppet_roles
        :param account_id: The account id that is being used. IAM wrapper returns this number
        :type account_id: int
        :return: Array of strings of valid puppet_roles
        :rtype: array
        '''
        images = self.get_images(account_id=account_id, filters=[{'Name': "tag-key", 'Values': ['Puppet_role']}])
        stacks = {}
        for i in images:
            v = Misc.get_value_from_array_hash(dictlist=i['Tags'], key='Puppet_role')
            if v is not "" and v is not None:
                stacks[v] = 1
        stacks = stacks.keys()
        logger.debug("Active stacks: " + str(stacks))
        return stacks

    def get_images(self, account_id, filters=None):
        '''
        This function returns and filters the AMI's in an account
        :param account_id: The account id that is being used. IAM wrapper returns this number
        :type account_id: int
        :param filters: The boto3 filter to be used
        :type filters: array of hash
        :return: Array of Ec2.Images
        :rtype: array
        '''
        logger.debug("filters is: %s" % (filters,))
        if not filters:
            filters = []
        filters.append({'Name': 'owner-id', 'Values': [account_id]})
        images = self.ec2_client.describe_images(Filters=filters)
        super(Ec2, self).query_information(query=images)
        i = []
        for image in images['Images']:
            i.append(image)
        return i

    def generate_ec2_unique_name(self, env, puppet_role, num):
        """
        This function generates x number of unique ec2 instance names
        :param env: Which environment should the names be generated to
        :param puppet_role: What is the puppet_role being used
        :param num: How many name should be generated
        :return: An array of of names generated
        """
        ret = []
        for i in range(num):
            name = None
            logger.debug("Arguments are: env: %s, puppet_role: %s" % (env, puppet_role))
            while name is None:
                name = env + '-' + puppet_role + '-' + Misc.random3digit()
                name = self.ec2_instance_name_exist(name=name)
                logger.info("Generated instance name is %s" % (name,))
                if name and name not in ret:
                    ret.append(name)
                else:
                    name = None
        return ret

    def ec2_instance_name_exist(self, name):
        """
        This function is used to determine if an ec2 instance name is unique or already exists
        :param name: the name that should be tested
        :return: If none is returned the name already existed, if unique the name is returned
        """
        reservations = self.get_ec2_instances(filters=[{'Name': 'tag:Name', 'Values': [name]}])
        instances = [i for r in reservations for i in r.instances]
        ret = None
        if not instances:
            logger.debug("Generated name is '%s'" % (name,))
            ret = name
        return ret

    def get_ec2_instances(self, filters=None):
        """
        This function returns a list of ec2 instances, which can be filtered
        :param filters: boto3 filter to use for filtering
        :return: A list of boto3.Instances
        """
        if filters:
            instances = self.ec2_client.describe_instances(Filters=filters)
        else:
            instances = self.ec2_client.describe_instances()
        super(Ec2, self).query_information(query=instances)
        i = []
        if len(instances['Reservations']) > 0:
            for res in instances['Reservations']:
                for instance in res['Instances']:
                    i.append(instance)
        logger.debug("Instances are: %s" % (i,))
        return i

    def get_security_group_ids_for_stack(self, puppet_role, vpcid, ostype, xively_service):
        """
        This function returns security group ids that should be attached to a machine.
        :param puppet_role: The puppet_role
        :param vpcid: The vpcid where the instance is
        :param ostype: What Ostype the machine is
        :param xively_service: The xively servie of the machine
        :return: A list of maximum 3 security group objects
        """
        result = []
        osgroups = self.get_security_groups(
            filters=[{'Name': 'tag:Os', 'Values': [ostype]}, {'Name': 'vpc-id', 'Values': [vpcid]}])
        logger.debug("Osgroups is : %s" % (osgroups,))
        for g in osgroups:
            result.append(g.get('GroupId'))
        logger.debug("OS security groups %s" % (len(osgroups, )))
        # First we search for puppet role specific security group, without xively service
        stackgroups = self.get_security_groups(
            filters=[{'Name': 'tag:Puppet_role', 'Values': [puppet_role]}, {'Name': 'vpc-id', 'Values': [vpcid]},
                     {'Name': 'tag:Xively_service', 'Values': [""]}])
        logger.debug("Stackgroups is : %s" % (stackgroups,))
        for s in stackgroups:
            result.append(s.get('GroupId'))
        logger.debug("PR security groups %s" % (len(stackgroups, )))
        if xively_service != "":
            xsgroups = self.get_security_groups(filters=[{'Name': 'tag:Puppet_role', 'Values': [puppet_role]},
                                                         {'Name': 'tag:Xively_service', 'Values': [xively_service]},
                                                         {'Name': 'vpc-id', 'Values': [vpcid]}])
            logger.debug("Xsgroups is : %s" % (xsgroups,))
            for x in xsgroups:
                result.append(x.get('GroupId'))
            logger.debug("XS security groups %s" % (len(xsgroups, )))
        return result

    def get_security_groups(self, filters=None, groupids=None):
        """
        This function returns security groups and can filter them
        :param filters: The boto3 filter that should be used
        :param groupids: The security group id's that shoud only be returned
        :return: a list of boto3.securitygroup's
        """
        if filters:
            sgs = self.ec2_client.describe_security_groups(Filters=filters)
        elif groupids:
            sgs = self.ec2_client.describe_security_groups(GroupIds=groupids)
        else:
            sgs = self.ec2_client.describe_security_groups()
        super(Ec2, self).query_information(query=sgs)
        ret = []
        for s in sgs['SecurityGroups']:
            ret.append(s)
        return ret

    def get_subnet_with_algorithym(self, puppet_role, subnets, num, fillup, xively_service):
        """
        This function returns subnets in order they should be used to fill up
        accordng to requested algorithym
        :param puppet_role: the puppet role of the requested instances
        :param subnets: all the subnets that are avaiable
        :param num: The number of subnets we should return
        :param fillup: Should fillup or round robin algorithym be used
        :param xively_service: the xively service of the requested instance
        :return: a list of instances in order they should be used
        """
        ordered = {}
        for subnet in subnets:
            instances = self.get_ec2_instances(filters=[{'Name': 'tag:Puppet_role', 'Values': [puppet_role]},
                                                        {'Name': 'tag:Xively_service', 'Values': [xively_service]},
                                                        {'Name': 'subnet-id', 'Values': [subnet.get('SubnetId')]}])
            ordered[subnet.get('SubnetId')] = len(instances)
        ordered = sorted(ordered.items(), key=operator.itemgetter(1))
        logger.debug("The ordered subnet list is: %s" % (str(ordered),))
        ret = []
        for i in range(0, num):
            if fillup:
                cur = ordered.pop(0)
                ret.append(cur[0])
                tmp = {}
                for item in ordered:
                    tmp[item[0]] = item[1]
                tmp[cur[0]] = cur[1] + 1
                ordered = sorted(tmp.items(), key=operator.itemgetter(1))
            else:
                mod = i % len(ordered)
                ret.append(ordered[mod][0])
        return ret

    def run_instance(self, baseamiid=None, key_name=None, securitygroup=None, instancetype=None, monitoring=None,
                     subnet=None, shutdown=None, user_data=None, ebsoptimized=None, dry_run=None, iam_name=None):
        """
        This function will create and start an ec2 instance
        :param baseamiid: the id of the ami to use as base
        :param key_name: the aws keypair to use
        :param securitygroup: the security groups to attach
        :param instancetype: the instance type to use
        :param monitoring: Should monitoring be enabled
        :param subnet: the subnet to provision the machine to
        :param shutdown: the shutdown behavior to use
        :param user_data: the machines user_data to run at first start
        :param ebsoptimized: should the machine be ebs optimized
        :param dry_run: should there be any changes done or just test
        :param iam_name: the IAM profile to use
        :return:
        """
        reservations = self.ec2_client.run_instances(ImageId=baseamiid,
                                                     KeyName=key_name,
                                                     SecurityGroupIds=securitygroup,
                                                     InstanceType=instancetype,
                                                     Monitoring={'Enabled': monitoring},
                                                     EbsOptimized=ebsoptimized,
                                                     SubnetId=subnet,
                                                     InstanceInitiatedShutdownBehavior=shutdown,
                                                     UserData=user_data,
                                                     MinCount=1,
                                                     MaxCount=1,
                                                     IamInstanceProfile={'Name': iam_name},
                                                     DryRun=dry_run)
        super(Ec2, self).query_information(query=reservations)
        inst = reservations['Instances'].pop()
        self.ec_launch_status(instanceids=[inst.get('InstanceId')], dryrun=dry_run)
        return inst

    def ec_launch_status(self, instanceids, dryrun):
        """
        This function uses the waiter to wait till the instance reaches a running state
        :param instanceids: The instance object returned by describe_intance or run_instance
        :type instanceids: boto3.Ec2
        :param dryrun: If the operation is only dryrun, and no changes should be done
        :type dryrun: bool
        :return: None
        """
        logger.info("Checking launch status of %s" % (instanceids,))
        waiter = self.ec2_client.get_waiter('instance_running')
        waiter.wait(DryRun=dryrun, InstanceIds=instanceids)

    def tag_resource(self, tags, instanceid):
        """
        This function tags a ec2 resource
        :param tags: A dict of key:value tags
        :type tags: dict
        :param id: The id of the instance to tag
        :return:
        """
        for key in tags.keys():
            logger.debug("Adding tag to resource %s" % (key,))
            ret = self.ec2_client.create_tags(Resources=[instanceid], Tags=[{'Key': key, 'Value': tags[key]}])
            super(Ec2, self).query_information(query=ret)

    def terminate_instance(self, instanceids, dryrun):
        try:
            resp = self.ec2_client.terminate_instances(DryRun=dryrun, InstanceIds=instanceids)
            super(Ec2, self).query_information(query=resp)
        except Exception as e:
            logger.warning("Exception for termination %s" % (e))
            return True
        ret = []
        for i in resp['TerminatingInstances']:
            ret.append({'id': i['InstanceId'], 'cur_state': i['CurrentState']['Name'],
                        'prev_state': i['PreviousState']['Name']})
        return ret

    def stop_instances(self,instanceids,dryrun):
        try:
            resp = self.ec2_client.stop_instances(DryRun=dryrun, InstanceIds=instanceids)
            super(Ec2, self).query_information(query=resp)
        except Exception as e:
            logger.warning("Exception for Stopping %s" % (e))
            return True
        ret = []
        for i in resp['StoppingInstances']:
            ret.append({'id': i['InstanceId'], 'cur_state': i['CurrentState']['Name'],
                        'prev_state': i['PreviousState']['Name']})
        return ret