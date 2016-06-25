from misc.Logger import logger
from misc import Misc
from wrapper.wrapper_base import wrapper_base


class Ami(wrapper_base):
    def __init__(self, session):
        """
        This function creates the initial client and resource objects
        :param session: a boto3 session object for connecting to aws
        :return: a wrapper.Ami object for running wrapper commands
        """
        logger.debug("Starting Ami wrapper")
        self.ami_client = session.client(service_name="ec2")
        self.ami_resource = session.resource(service_name="ec2")

    def information_ami(self, filters):
        if filters:
            images = self.ami_client.describe_images(Filters=filters, Owners=["self"])
        else:
            images = self.ami_client.describe_images(Owners=["self"])
        super(Ami, self).query_information(query=images)
        return images['Images']

    def get_all_image_instances(self, imageid):
        if imageid:
            instances = self.ami_client.describe_instances(Filters=[{'Name': 'image-id', 'Values': [imageid]}])
        else:
            instances = self.ami_client.describe_instances()
        super(Ami, self).query_information(query=instances)
        temp = {}
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                if 'Tags' in instance:
                    value = Misc.get_value_from_array_hash(dictlist=instance.get('Tags'), key='Name')
                else:
                    value = instance.get('InstanceId')
                if instance['ImageId'] not in temp:
                    temp[instance['ImageId']] = [value]
                else:
                    temp[instance['ImageId']].append(value)
        ret = []
        for imageid in temp:
            img = {'ImageId': imageid}
            img['InstanceCount'] = len(temp[imageid])
            img['Instances'] = temp[imageid]
            ret.append(img)
        return ret
