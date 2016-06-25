import boto3
import os
import yaml
from misc.Logger import logger
from misc import Misc
from wrapper.ec2 import Ec2
from wrapper.vpc import Vpc


class CloudWatch(object):
    def __init__(self):
        logger.debug("Starting Class for Cloudwatch")
        try:
            config_file = open("%s/etc/aws.conf" % (os.environ['KERRIGAN_ROOT'],), 'r')
            self.yaml = yaml.load(config_file)
        except IOError as e:
            logger.error("aws.conf I/O error({0}): {1}".format(e.errno, e.strerror))
        self.cloudwatch = boto3.client('cloudwatch', region_name='us-east-1')

    def create_alarm_for_auto_scaling_group(self, env=None, stack=None, xively_service=None):
        alarm_name = "%s-%s-%s" % (env, stack, xively_service)
        alarm_description = alarm_name + " alarm if CPU >= 60"
        actions_enabled = True
        ok_actions = []
        ok_actions.append("arn:aws:sns:us-east-1:462322024086:Scaling-Event")
        alarm_actions = []
        alarm_actions.append("arn:aws:sns:us-east-1:462322024086:Scaling-Event")
        metric_name = "CPUUtilization"
        namespace = "EC2"
        statistic = "Average"
        dimensions = [{'Name': 'AutoScalingGroupName', 'Value': alarm_name}]
        period = 60
        unit = "Seconds"
        eval_period = 5
        threshold = 60
        comparison_operator = "GreaterThanOrEqualToThreshold"

        self.cloudwatch.put_metric_alarm(AlarmName=alarm_name, AlarmDescription=alarm_description,
                                         ActionsEnabled=actions_enabled, OKActions=ok_actions,
                                         AlarmActions=alarm_actions,
                                         MetricName=metric_name, Namespace=namespace, Statistic=statistic,
                                         Dimensions=dimensions, Period=period, Unit=unit, EvaluationPeriods=eval_period,
                                         Threshold=threshold, ComparisonOperator=comparison_operator)
