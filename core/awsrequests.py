from misc.Logger import logger
from core.base import base
from misc import Misc


class awsrequests(base):
    def __init__(self, session):
        logger.debug("Starting awsrequests")
        self.session = session

    def information_ec2_instances(self, columns, filters):
        '''
        This function gathers information about ec2 instances
        :param columns: The requested columns that should be returned
        :type columns: array
        :param filters: The boto3 filters that should be used for filtering the results
        :type filters: array
        :return: an array with parsed instances for printing
        :rtype: array
        '''
        from wrapper.ec2 import Ec2
        from misc import Misc
        ec2 = Ec2(session=self.session)
        result = ec2.information_ec2_instances(filters=filters)
        ret = []
        for instance in result:
            ret.append(Misc.parse_object(object=instance, columns=columns, service="ec2"))
        return ret

    def information_apigateway(self, columns):
        from wrapper.apigateway import Apigateway
        from misc import Misc
        apigateway = Apigateway(session=self.session)
        result = apigateway.information_apigateway()
        ret = []
        for instance in result:
            ret.append(Misc.parse_object(object=instance, columns=columns, service="apigateway"))
        return ret

    def information_cloudformation(self, columns):
        from wrapper.cloudformation import Cloudformation
        from misc import Misc
        cloudformation = Cloudformation(session=self.session)
        stacks = cloudformation.describe_stacks()
        ret = []
        for stack in stacks:
            ret.append(Misc.parse_object(service="cloudformation", object=stack, columns=columns))
        return ret

    def information_kinesis(self, columns):
        from wrapper.kinesis import Kinesis
        from misc import Misc
        kinesis = Kinesis(session=self.session)
        streams = kinesis.information_kinesis_streams()
        ret = []
        for stream in streams:
            ret.append(Misc.parse_object(service="kinesis", object=stream, columns=columns))
        return ret

    def information_ami(self, columns, filters):
        from wrapper.ami import Ami
        from misc import Misc
        ami = Ami(session=self.session)
        result = ami.information_ami(filters=filters)
        ret = []
        for instance in result:
            ret.append(Misc.parse_object(object=instance, columns=columns, service="ami"))
        return ret

    def information_vpc(self, columns, filters):
        from wrapper.vpc import Vpc
        from misc import Misc
        vpc = Vpc(session=self.session)
        result = vpc.information_vpc(filters=filters)
        ret = []
        for instance in result:
            ret.append(Misc.parse_object(object=instance, columns=columns, service="vpc"))
        return ret

    def information_elbs(self, columns, filters):
        from wrapper.elb import Elb
        from misc import Misc
        elb = Elb(session=self.session)
        result = elb.information_elbs(filters=filters)
        ret = []
        for elb_object in result:
            ret.append(Misc.parse_object(object=elb_object, columns=columns, service="elb"))
        return ret

    def image_instance_status(self, imageid):
        from wrapper.ami import Ami
        from misc import Misc
        ami = Ami(session=self.session)
        result = ami.get_all_image_instances(imageid=imageid)
        return result

    def service_supported_columns(self, service):
        '''
        This function returns the current supported columns for printing and parsing
        :return: An array with currently supported column attributes for printing
        :rtype: array
        '''
        from misc import Misc
        return Misc.get_supported_columns(service=service)

    def get_active_envs(self):
        """
        This function returns all active VPC environments in an account
        :return: a dict containing the tags
        """
        from wrapper.vpc import Vpc
        vpc = Vpc(session=self.session)
        return vpc.get_active_envs()

    def get_ami_stacks(self):
        """
        This function returns all ami stacks in an account
        :return: a dict containing the puppet_roles
        """
        from wrapper.ec2 import Ec2
        from wrapper.iam import Iam
        ec2 = Ec2(session=self.session)
        iam = Iam(session=self.session)
        account_id = iam.get_account_id()
        return ec2.get_ami_stacks(account_id=account_id)

    def get_ami_from_tag(self, puppet_role):
        from wrapper.ec2 import Ec2
        from wrapper.iam import Iam
        ec2 = Ec2(session=self.session)
        iam_modul = Iam(session=self.session)
        account_id = iam_modul.get_account_id()
        baseami_object = ec2.get_images(account_id=account_id,
                                        filters=[{'Name': 'tag:Puppet_role', 'Values': [puppet_role]}])[0]
        return baseami_object

    def create_ec2_instance(self, puppet_role, env, requester, customer, xively_service, base_ami, iam, instance_type,
                            dry_run, shutdown, monitoring, fillup, num, keypair, availability=None):
        """
        This function creates an ec2 instance
        :param puppet_role: the Puppet_role that should be used
        :param env:  the environment where we should provision to
        :param requester: the user/team requesting the machine
        :param customer: For future use only
        :param xively_service: the Xively_service that should be used
        :param base_ami: the base_ami that should be used. Can default to puppet_role
        :param iam: The iam role that should be attached, defaults to ec2-base
        :param instance_type: the type of instance requested
        :param dry_run: No changes should be done
        :param shutdown: The shutdown behavior to use
        :param monitoring: Should monitoring be enabled
        :param fillup: Should fillup algorithym be used or round robin
        :param num: the number of instances
        :return: a list of instance objects
        """
        from wrapper.ec2 import Ec2
        from wrapper.vpc import Vpc
        from misc import Misc
        from core.stackdata import stackdata
        stackdata_object = stackdata(session=self.session)
        ec2 = Ec2(session=self.session)
        vpc = Vpc(session=self.session)
        lambda_function_args = {'env': env, 'puppet_role': puppet_role, 'requester': requester,
                                'xively_service': xively_service,
                                'customer': customer, 'shutdown': shutdown, 'dry_run': dry_run}
        stack_data = stackdata_object.get_stack_data(puppet_role=puppet_role, xively_service=xively_service)
        vpc_obj = vpc.get_vpc_from_env(env=env)
        ## Find the baseami object that needs to be used
        if base_ami:
            base_ami = base_ami
        elif 'ami' in stack_data:
            base_ami = stack_data['ami']
        else:
            logger.info("Falling back to puppet_role as AMI name")
            base_ami = puppet_role
        logger.info("The baseami that is going to be used: %s" % (base_ami,))
        baseami_object = self.get_ami_from_tag(puppet_role=base_ami)

        ## Get values for lambda function
        lambda_function_args['baseamiid'] = baseami_object.get('ImageId')
        if (availability == None):
            availability = Misc.get_value_from_array_hash(dictlist=baseami_object.get('Tags'), key='Availability')
        lambda_function_args['ostype'] = Misc.get_value_from_array_hash(dictlist=baseami_object.get('Tags'), key='Os')
        if keypair is not None:
            lambda_function_args['keypair'] = keypair
        else:
            lambda_function_args['keypair'] = Misc.get_value_from_array_hash(dictlist=vpc_obj.get('Tags'),
                                                                             key='Keypair')

        ## Find the instance_type that needs to be used
        if instance_type:
            inst_type_final = instance_type
        elif 'instance_type' in stack_data and env in stack_data['instance_type']:
            inst_type_final = stack_data['instance_type'][env]
        else:
            inst_type_final = Misc.get_value_from_array_hash(dictlist=baseami_object.get('Tags'), key='Instancetype')
        logger.info("Instance type that will be used: %s" % (inst_type_final,))
        lambda_function_args['instance_type'] = inst_type_final

        ## Find the instance profile that needs to be used
        if iam:
            iam_name = iam
        elif 'iam' in stack_data:
            iam_name = "%s-%s" % (env, stack_data['iam']['name_postfix'])
        else:
            iam_name = "ec2-base"
        logger.info("Base iam instance profile name: %s" % (iam_name,))
        lambda_function_args['iam'] = iam_name

        ## Find value for ebsoptimized
        if 'ebsoptimized' in stack_data and env in stack_data['ebsoptimized']:
            lambda_function_args['ebsoptimized'] = Misc.str2bool(stack_data['ebsoptimized'][env])
        else:
            lambda_function_args['ebsoptimized'] = False

        ## Find value for monitoring enablement
        if monitoring:
            lambda_function_args['monitoring'] = monitoring
        elif 'monitoring' in stack_data and env in stack_data['monitoring']:
            lambda_function_args['monitoring'] = Misc.str2bool(stack_data['monitoring'][env])
        else:
            lambda_function_args['monitoring'] = False

        ## Generate instance names for all required instances
        lambda_function_args['instance_name'] = ec2.generate_ec2_unique_name(env=env, puppet_role=puppet_role, num=num)
        ## Gather all security groups needed for creating an instance stack
        lambda_function_args['securitygroup'] = ec2.get_security_group_ids_for_stack(vpcid=vpc_obj.get('VpcId'),
                                                                                     puppet_role=puppet_role,
                                                                                     ostype=lambda_function_args[
                                                                                         'ostype'],
                                                                                     xively_service=xively_service)
        # We need to retrieve the subnets from Vpc object, and pass it to Ec2 object
        subnets = vpc.get_all_subnets(filters=[{'Name': 'tag:Network', 'Values': [availability]},
                                               {'Name': 'vpc-id', 'Values': [vpc_obj.get('VpcId')]}])
        lambda_function_args['subnet'] = ec2.get_subnet_with_algorithym(puppet_role=puppet_role,
                                                                        subnets=subnets, num=num,
                                                                        fillup=fillup, xively_service=xively_service)
        instances = Misc.parallel_map_reduce(
            lambda x: self.create_instance_lamdba(args=lambda_function_args),
            lambda x, y: x + [y], xrange(0, num), [])
        return instances

    def create_instance_lamdba(self, args=None):
        """
        This function is invoked by lambda to provision multiple at same time
        :param args: A dict with keypairs needed
        :return: instance objects created
        """
        from wrapper.ec2 import Ec2
        from wrapper.iam import Iam
        ec2 = Ec2(session=self.session)
        iam = Iam(session=self.session)
        account_id = iam.get_account_id();
        inst_name = args['instance_name'].pop()
        # linux or windows userdata formated for start
        if 'snappyindex' in args:
            logger.debug("Deploying a snappyindex")
            snappyindex = args['snappyindex'].pop()
            userdata = args['userdata']
            userdata = userdata.format(index=snappyindex, accountid=args['accountid'],
                                       channelname=args['channelname'], newrelic=args['newrelic'],
                                       broker=args['broker'], hostname=inst_name, env=args['env'],
                                       devicestring=args['devicestring'], branch=args['branch'])
        elif 'userdata' in args:
            userdata = args['userdata']
        else:
            userdata = Misc.get_userdata_for_os(ostype=args['ostype']).format(hostname=inst_name, env=args['env'], account=account_id)
        instance = ec2.run_instance(baseamiid=args['baseamiid'], key_name=args['keypair'],
                                    securitygroup=args['securitygroup'],
                                    instancetype=args['instance_type'], subnet=args['subnet'].pop(),
                                    user_data=userdata,
                                    shutdown=args['shutdown'], monitoring=args['monitoring'],
                                    ebsoptimized=args['ebsoptimized'], dry_run=args['dry_run'], iam_name=args['iam'])
        # add snappyindex to tag
        if 'snappyindex' in args:
            ec2.tag_resource(instanceid=instance.get('InstanceId'),
                             tags={'Name': inst_name, 'Requester': args['requester'],
                                   'Puppet_role': args['puppet_role'], 'Xively_service': args['xively_service'],
                                   'Customer': args['customer'],
                                   'Snappy_index': str(snappyindex),
                                   'Environment': args['env']})
        else:
            ec2.tag_resource(instanceid=instance.get('InstanceId'),
                             tags={'Name': inst_name, 'Requester': args['requester'],
                                   'Puppet_role': args['puppet_role'], 'Xively_service': args['xively_service'],
                                   'Customer': args['customer'],
                                   'Environment': args['env']})
        return instance

    def deploy_stack_to_env(self, env, file, dryrun):
        stack_json = Misc.parse_file_to_json(file=file)
        from misc import Validator
        stack_json = Validator.validate_kerrigan_json(stack_data=stack_json, env=env)
        if 'cloudformation' in stack_json:
            cloudformation_json = stack_json.pop("cloudformation")
            from misc import Translater
            from wrapper.vpc import Vpc
            from wrapper.cloudformation import Cloudformation
            vpc = Vpc(session=self.session)
            cloudformation = Cloudformation(session=self.session)
            env_vpc = vpc.get_vpc_from_env(env=env)
            env_cidr = env_vpc['CidrBlock']
            ami = self.get_ami_from_tag(puppet_role=stack_json['ami'])
        else:
            cloudformation_json = None
        self.upload_stack_to_dynamodb(item=stack_json)
        # Do changes from kerrigan
        if cloudformation_json:
            logger.info(msg="Doing security group transformations")
            cloudformation_json = Translater.translate_security_group_ip_address_in_cloudformation(
                cloudformation_json=cloudformation_json, env_cidr=env_cidr)
            cloudformation_parameters = Translater.gather_information_for_cloudofrmation_parameters(
                stack_data=stack_json, vpc=env_vpc, ami=ami)
        # Do pre kerrigan tasks
        # Do cloudformation
        if cloudformation_json:
            stackname = "%s-%s-%s" % (env, stack_json['puppet_role'], stack_json['xively_service'])
            if cloudformation.stack_exists(stackname=stackname):
                cloudformation.update_stack(stackname=stackname, templatebody=cloudformation_json, dryrun=dryrun,
                                            parameters=cloudformation_parameters)
            else:
                cloudformation.create_stack(stackname=stackname, templatebody=cloudformation_json, dryrun=dryrun,
                                            parameters=cloudformation_parameters)
                # do post kerrigan tasks

    def create_s3_bucket(self, name, location):
        """
        This function creates an s3 bucket
        :param name: Name of the bucket
        :param location: The location constraint to use
        :return: The created bucket object
        """
        from wrapper.s3 import S3
        s3 = S3(session=self.session)
        resp = s3.create_bucket(name=name, location=location)
        return resp

    def create_cloudformation_stack(self, stackname, parameters=None, templatebody=None, templateurl=None):
        """
        This function creates cloudformation stacks with requested data
        :param stackname: the name of the coudformation stack
        :param parameters: the parameters that are required for the cloudformation stack
        :param templatebody: The body of the document for the stack
        :param templateurl: The s3 url where the template can be reached
        :return: The created cloudformation stack object
        """
        from wrapper.cloudformation import Cloudformation
        cloudformation = Cloudformation()
        resp = cloudformation.create_stack(stackname=stackname, parameters=parameters, templatebody=templatebody,
                                           templateurl=templateurl)
        return resp

    def iam_user_exists(self, username):
        """
        This function tests if an iam user exists or not
        :param username: the iam username
        :return: true or false
        :rtype: bool
        """
        from wrapper.iam import Iam
        iam = Iam(session=self.session)
        ret = iam.iam_user_exists(username=username)
        return ret

    def create_iam_user(self, username, dryrun, path):
        """
        This function creates an iam user
        :param username: The requested username
        :param dryrun: No changes should be done
        :param path: the path for the user. defaults to "/"
        :return: the object of the created user
        """
        from wrapper.iam import Iam
        iam = Iam(session=self.session)
        ret = iam.create_iam_user(username=username, dryrun=dryrun, path=path)
        return ret

    def iam_user_groups(self, username):
        """
        This function lists groups of a user
        :param username: the user whoes groups should be listed
        :return:
        """
        from wrapper.iam import Iam
        iam = Iam(session=self.session)
        ret = iam.list_user_groups(username=username)
        return ret

    def add_iam_user_to_group(self, username, groupname):
        """
        This function adds an iam user to a group
        :param username: the username to add
        :param groupname: The group where it should be added
        :return:
        """
        from wrapper.iam import Iam
        iam = Iam(session=self.session)
        ret = iam.add_iam_user_to_group(username=username, groupname=groupname)
        return ret

    def create_iam_login_profile(self, username, password):
        """
        This function creates a login profile for an iam user
        :param username: the username that should have the profile added
        :param password: the password to create initially
        :return:
        """
        from wrapper.iam import Iam
        iam = Iam(session=self.session)
        ret = iam.create_iam_login_profile(username=username, password=password)
        return ret

    def get_login_profile(self, username):
        """
        This function is used to validate if a user has a login profile or should have one created
        :param username: the username to validate
        :return: the login profile information if user has one
        """
        from wrapper.iam import Iam
        iam = Iam(session=self.session)
        ret = iam.get_login_profile(username=username)
        return ret

    def terminate_instance(self, dryrun, instanceids):
        """
        This function is used to terminate instance-s within AWS
        :param dryrun: No change should be performed, only validation is done
        :type dryrun: bool
        :param instanceids: an array of instance id's to terminate
        :type instanceids: dict
        :return: An array with dicts
        :rtype: array
        """
        from wrapper.ec2 import Ec2
        ec2 = Ec2(session=self.session)
        ret = ec2.terminate_instance(dryrun=dryrun, instanceids=instanceids)
        return ret

    def upload_stack_to_dynamodb(self, item):
        from wrapper.dynamodb import Dynamodb
        dynamodb = Dynamodb(session=self.session)
        landscape_tablename = Misc.landscape_dynamo_table_name
        resp = dynamodb.put_item(tablename=landscape_tablename, item=item)
        return resp

    def deploy_snappy(self, env, num, dryrun, accountid, newrelic, channelname, devicestring, branch):
        from wrapper.ec2 import Ec2
        from wrapper.vpc import Vpc
        ec2 = Ec2(session=self.session)
        vpc = Vpc(session=self.session)
        vpc_obj = vpc.get_vpc_from_env(env=env)
        num = int(num)
        snappyindex = self.get_snappy_index(num=num, vpcid=vpc_obj.get('VpcId'))
        lambda_function_args = {'env': "infra", 'puppet_role': 'benchmarkslave', 'requester': "benchmark",
                                'xively_service': "benchmark_slave",
                                'customer': "", 'shutdown': "stop", 'dry_run': dryrun, 'base_ami': "benchmarkslave",
                                'instance_type': 'c3.xlarge', 'snappyindex': snappyindex, 'accountid': accountid,
                                'channelname': channelname, 'newrelic': newrelic, 'iam': 'infra-benchmarkslave',
                                'ebsoptimized': False, 'monitoring': False, 'devicestring': devicestring,
                                'branch': branch}
        lambda_function_args['userdata'] = Misc.get_userdata_for_os(ostype="snappy")
        baseami_object = self.get_ami_from_tag(puppet_role=lambda_function_args['base_ami'])
        lambda_function_args['baseamiid'] = baseami_object.get('ImageId')
        availability = Misc.get_value_from_array_hash(dictlist=baseami_object.get('Tags'), key='Availability')
        lambda_function_args['ostype'] = Misc.get_value_from_array_hash(dictlist=baseami_object.get('Tags'), key='Os')
        lambda_function_args['keypair'] = Misc.get_value_from_array_hash(dictlist=vpc_obj.get('Tags'),
                                                                         key='Keypair')
        lambda_function_args['instance_name'] = ec2.generate_ec2_unique_name(env=env, puppet_role="benchmarkslave",
                                                                             num=num)
        lambda_function_args['securitygroup'] = ec2.get_security_group_ids_for_stack(vpcid=vpc_obj.get('VpcId'),
                                                                                     puppet_role="benchmarkslave",
                                                                                     ostype=lambda_function_args[
                                                                                         'ostype'],
                                                                                     xively_service="benchmark_slave")
        subnets = vpc.get_all_subnets(filters=[{'Name': 'tag:Network', 'Values': [availability]},
                                               {'Name': 'vpc-id', 'Values': [vpc_obj.get('VpcId')]}])
        lambda_function_args['subnet'] = ec2.get_subnet_with_algorithym(puppet_role="benchmarkslave",
                                                                        subnets=subnets, num=num,
                                                                        fillup=False, xively_service="benchmark_slave")
        ## Get broker IP address
        broker = ec2.get_ec2_instances(filters=[{'Name': 'vpc-id', 'Values': [vpc_obj.get('VpcId')]},
                                                {'Name': 'tag:Xively_service', 'Values': ['benchmark_master']},
                                                {'Name': 'tag:Puppet_role', 'Values': ['linuxbase']}])
        lambda_function_args['broker'] = broker[0].get('PrivateIpAddress') + ":8883"
        instances = Misc.parallel_map_reduce(
            lambda x: self.create_instance_lamdba(args=lambda_function_args),
            lambda x, y: x + [y], xrange(0, num), [])
        return instances

    def prepare_deployment(self, puppet_role, xively_service, env, num, instance_type, base_ami, iam, requester,
                           customer, dry_run):
        from wrapper.ec2 import Ec2
        from wrapper.vpc import Vpc
        ec2 = Ec2(session=self.session)
        vpc = Vpc(session=self.session)
        vpc_obj = vpc.get_vpc_from_env(env=env)
        filter_base = [{'Name': 'vpc-id', 'Values': [vpc_obj.get('VpcId')]}]
        if xively_service:
            old_machines = ec2.get_ec2_instances(
                filters=filter_base + [{'Name': 'tag:Puppet_role', 'Values': [puppet_role]},
                                       {'Name': 'tag:Xively_service', 'Values': ["%s_old" % xively_service]}])
            rollback_machines = ec2.get_ec2_instances(
                filters=filter_base + [{'Name': 'tag:Puppet_role', 'Values': [puppet_role]},
                                       {'Name': 'tag:Xively_service', 'Values': ["%s_rollback" % xively_service]}])
            current_machines = ec2.get_ec2_instances(
                filters=filter_base + [{'Name': 'tag:Puppet_role', 'Values': [puppet_role]},
                                       {'Name': 'tag:Xively_service', 'Values': [xively_service]}])
        else:
            old_machines = ec2.get_ec2_instances(
                filters=filter_base + [{'Name': 'tag:Puppet_role', 'Values': ["%s_old" % puppet_role]}])
            rollback_machines = ec2.get_ec2_instances(
                filters=filter_base + [{'Name': 'tag:Puppet_role', 'Values': ["%s_rollback" % puppet_role]}])
            current_machines = ec2.get_ec2_instances(
                filters=filter_base + [{'Name': 'tag:Puppet_role', 'Values': [puppet_role]}])
        for old_machine in old_machines:
            logger.info(msg="Going to stop old machine %s" % old_machine.get('InstanceId'))
            ec2.stop_instances(dryrun=dry_run, instanceids=[old_machine.get('InstanceId')])
        for rollback_machine in rollback_machines:
            logger.info(msg="Going to stop old machine %s" % rollback_machine.get('InstanceId'))
            ec2.stop_instances(dryrun=dry_run, instanceids=[rollback_machine.get('InstanceId')])
            if xively_service:
                ec2.tag_resource(instanceid=rollback_machine.get('InstanceId'),
                                 tags={'Xively_service': "%s_old" % xively_service})
            else:
                ec2.tag_resource(instanceid=rollback_machine.get('InstanceId'),
                                 tags={'Puppet_role': "%s_old" % puppet_role})
        for current_machine in current_machines:
            logger.info(msg="Going to retag current machine %s" % current_machine.get('InstanceId'))
            if xively_service:
                ec2.tag_resource(instanceid=current_machine.get('InstanceId'),
                                 tags={'Xively_service': "%s_rollback" % xively_service})
            else:
                ec2.tag_resource(instanceid=current_machine.get('InstanceId'),
                                 tags={'Puppet_role': "%s_rollback" % puppet_role})

    def get_snappy_index(self, num, vpcid):
        from wrapper.ec2 import Ec2
        ec2 = Ec2(session=self.session)
        indexes = []
        current = 1
        while len(indexes) < num:
            logger.info("Gathering snappyindex %s" % current)
            filters = [{'Name': 'tag:Snappy_index', 'Values': [str(current)]},
                       {'Name': 'instance-state-name', 'Values': ["running", "pending"]},
                       {'Name': 'vpc-id', 'Values': [vpcid]}]
            inst = ec2.information_ec2_instances(filters=filters)
            if len(inst) == 0:
                indexes.append(current)
                logger.info("Found snappy_index not in use: %s" % current)
            else:
                logger.info("Snappy index in use")
            current += 1
        return indexes

    def dump_apigateway(self, name):
        """
        This function returns a json object about an aws apigateway
        :param name: name of the apigateway to query
        :type name: basestring
        :return: the json object to dump
        """
        from wrapper.apigateway import Apigateway
        apigateway = Apigateway(session=self.session)
        ret = apigateway.information_apigateway(name=name)
        return ret

    def upload_apigateway(self, json, dryrun):
        """
        This function uploads an apigateway json to aws, and creates needed changes
        :param json: the json object
        :type json: json object
        :param dryrun: a boolean object if changes need to be made
        :type dryrun: bool
        :return: None
        """
        from wrapper.apigateway import Apigateway
        apigateway = Apigateway(session=self.session, dryrun=dryrun)
        logger.debug("Testing if rest api exists")
        if apigateway.apigateway_exists(name=json['name']):
            logger.debug("Need to test if description needs to be updated")
            rest_api = apigateway.get_rest_api_by_name(name=json['name'])
            rest_api_id = rest_api['id']
            if rest_api['description'] != json['description']:
                logger.info("Need to update the description")
                resp = apigateway.update_rest_api(restid=rest_api_id,
                                                  operation=[{'op': 'replace', 'path': '/description',
                                                              'value': json['description']}])
        else:
            rest_api_create_resp = apigateway.create_rest_api(name=json['name'], desc=json['description'])
            rest_api_id = rest_api_create_resp['id']
            if dryrun:
                logger.warning("Whole resource needs to be created, no point in continue")
                return None
        logger.info("The rest api id we are going to work on: %s" % rest_api_id)
        resource_hash = apigateway.generate_resourcehash(restid=rest_api_id)
        root_id = resource_hash['/']
        for resource in json['resources']:
            if resource['path'] not in resource_hash:
                logger.info("Need to create path in apigateway")
                resource_data = apigateway.create_resource(restid=rest_api_id, parentid=root_id,
                                                           pathpart=resource['pathPart'])
                resource_hash[resource['path']] = resource_data['id']
            for method in resource['resourceMethods']:
                apigateway.compare_method(restid=rest_api_id, resourceid=resource_hash[resource['path']], method=method,
                                          json_data=resource['resourceMethods'][method])
            resource_hash.pop(resource['path'])
        for remaining_resource in resource_hash:
            logger.warning("Need to delete following resources since not defined")
            apigateway.delete_resource(restid=rest_api_id, resourceid=resource_hash[remaining_resource])
