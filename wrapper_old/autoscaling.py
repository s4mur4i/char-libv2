import boto3
import os
import yaml
from misc.Logger import logger
from misc import Misc
from wrapper.ec2 import Ec2
from wrapper.vpc import Vpc
from wrapper.cloudwatch import CloudWatch


class AutoScaling(object):
    def __init__(self):
        logger.debug("Starting Class for Auto Scaling")
        try:
            config_file = open("%s/etc/aws.conf" % (os.environ['KERRIGAN_ROOT'],), 'r')
            self.yaml = yaml.load(config_file)
        except IOError as e:
            logger.error("aws.conf I/O error({0}): {1}".format(e.errno, e.strerror))
        self.autoscale = boto3.client('autoscaling', region_name='us-east-1')

    def get_launch_configs(self, launch_configs=None):
        if launch_configs:
            resp = self.autoscale.describe_launch_configurations(LaunchConfigurationNames=launch_configs)
        else:
            resp = self.autoscale.describe_launch_configurations()
        result = []
        for lc in resp['LaunchConfigurations']:
            logger.debug("Gathering info on %s" % (lc['LaunchConfigurationName']))
            result.append(lc)
            logger.debug("Launch Configuration information: %s" % (lc))
        return result

    def get_auto_scaling_groups(self, auto_scaling_groups=None):
        if auto_scaling_groups:
            resp = self.autoscale.describe_auto_scaling_groups(AutoScalingGroupNames=auto_scaling_groups)
        else:
            resp = self.autoscale.describe_auto_scaling_groups()
        result = []
        for asg in resp['AutoScalingGroups']:
            logger.debug("Gathering info on %s" % (asg['AutoScalingGroupName']))
            result.append(asg)
            logger.debug("Launch Configuration information: %s" % (asg))
        return result

    def create_launch_config(self, launch_config_name=None, env=None, xively_service=None, stack=None):
        e = Ec2()
        v = Vpc()
        vpc = v.get_vpc_from_env(env=env)
        keyname = Misc.get_value_from_array_hash(dictlist=vpc['Tags'], key='Keypair')
        baseami = e.query_base_image(stack=stack)
        ostype = Misc.get_value_from_array_hash(dictlist=baseami['Tags'], key='Os')
        instance_type = Misc.get_value_from_array_hash(dictlist=baseami['Tags'], key='Instancetype')
        image = baseami.get('ImageId')
        sgs = e.get_security_group_ids_for_launch(vpcid=vpc.get('VpcId'), stack=stack,
                                                  ostype=ostype, xively_service=xively_service)
        iam = "ec2"
        y = Misc.get_app_ports_yaml('app_ports')
        port = y[xively_service]
        userdata = Misc.get_autoscale_userdata_for_os(ostype=ostype).format(env=env, stack=stack,
                                                                            xively_service=xively_service,
                                                                            port=port)
        monitoring = {}
        monitoring['Enabled'] = True

        self.autoscale.create_launch_configuration(LaunchConfigurationName=launch_config_name, ImageId=image,
                                                   KeyName=keyname, SecurityGroups=sgs, UserData=userdata,
                                                   InstanceType=instance_type, InstanceMonitoring=monitoring,
                                                   IamInstanceProfile=iam)

    def generate_launch_config_name(self, env=None, stack=None, xively_service=None):
        launch_config_name = "%s-%s-%s" % (env, stack, xively_service)
        return launch_config_name

    def generate_auto_scaling_group_name(self, env=None, stack=None, xively_service=None):
        auto_scaling_group_name = "%s-%s-%s" % (env, stack, xively_service)
        return auto_scaling_group_name

    def check_launch_config_exists(self, env=None, xively_service=None, stack=None):
        launch_config_name = self.generate_launch_config_name(env=env, stack=stack, xively_service=xively_service)
        lcs = self.get_launch_configs()
        for l in lcs:
            if launch_config_name == l['LaunchConfigurationName']:
                logger.debug("Launch Configuration exists: %s" % launch_config_name)
                return True
        return False

    def check_auto_scaling_group_exists(self, auto_scaling_group_name=None):
        asg = self.get_auto_scaling_groups(auto_scaling_group_name)
        for g in asg:
            if auto_scaling_group_name[0] == g['AutoScalingGroupName']:
                logger.debug("Launch Configuration exists: %s" % auto_scaling_group_name)
                return True
        return False

    def run_auto_scaling_group(self, auto_scaling_group_name=None, min_size=None, max_size=None,
                               launch_config_name=None, load_balancer_name=None,
                               health_check=None, health_check_grace_period=None,
                               vpc_zones=None, tags=None):
        resp = self.autoscale.create_auto_scaling_group(AutoScalingGroupName=auto_scaling_group_name, MinSize=min_size,
                                                        MaxSize=max_size, LaunchConfigurationName=launch_config_name,
                                                        LoadBalancerNames=load_balancer_name,
                                                        HealthCheckType=health_check,
                                                        HealthCheckGracePeriod=health_check_grace_period,
                                                        VPCZoneIdentifier=vpc_zones, Tags=tags)

    def get_status_auto_scaling_group(self, auto_scaling_group_name=None):
        status = ""
        while status != 'Running':
            logger.info("Looping in Get Auto Scale group Status")
            resp = self.autoscale.describe_auto_scaling_groups(AutoScalingGroupNames=[auto_scaling_group_name])
            logger.info(resp)
            for asg in resp['AutoScalingGroups']:
                logger.info(asg)
                status = asg['Status']
            logger.info("Status: %s" % status)
        return status

    def create_scaling_policy(self, env=None, stack=None, xively_service=None):
        auto_scaling_group_name = self.generate_auto_scaling_group_name(env=env, stack=stack,
                                                                        xively_service=xively_service)
        policy_name = "%s-%s-%s" % (env, stack, xively_service)
        adjustment_type = "ChangeInCapacity"
        scaling_adjustment = 1
        cooldown = 500

        resp = self.autoscale.put_scaling_policy(AutoScalingGroupName=auto_scaling_group_name, PolicyName=policy_name,
                                                 AdjustmentType=adjustment_type, ScalingAdjustment=scaling_adjustment,
                                                 Cooldown=cooldown)
        if resp['PolicyARN']:
            logger.info("SUCCESS Creating Scaling Policy")
            return "Success"
        else:
            logger.info("FAILED Creating Scaling Policy")
            return "Failure"
