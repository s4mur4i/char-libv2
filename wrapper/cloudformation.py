from misc.Logger import logger
from misc import Misc
from wrapper.wrapper_base import wrapper_base
import json


class Cloudformation(wrapper_base):
    def __init__(self, session):
        '''
        This function creates the initial client and resource objects
        :param session: a boto3 session object for connecting to aws
        :return: a wrapper.Cloudformation object for running wrapper commands
        '''
        logger.debug("Starting cloudformation wrapper")
        self.cloudformation_client = session.client(service_name="cloudformation")
        self.cloudformation_resource = session.resource(service_name="cloudformation")

    def create_stack(self, stackname, parameters, dryrun, templatebody=None, templateurl=None):
        if dryrun:
            logger.warning("Dryrun requested not creating stack: %s" % (stackname,))
            return None
        args = {'StackName': stackname, "Capabilities": ['CAPABILITY_IAM' ]}
        if parameters:
            args['Parameters'] = parameters
        if templatebody:
            args['TemplateBody'] = json.dumps(templatebody)
        elif templateurl:
            args['TemplateUrl'] = templateurl
        else:
            logger.error("No body or URL given for stack")
            raise ValueError
        resp = self.cloudformation_client.create_stack(**args)
        super(Cloudformation, self).query_information(query=resp)
        resp.pop('ResponseMetadata')
        return resp

    def describe_stacks(self, stackname=None):
        if stackname:
            ret = self.cloudformation_client.describe_stacks(StackName=stackname)
        else:
            ret = self.cloudformation_client.describe_stacks()
        super(Cloudformation, self).query_information(query=ret)
        return ret['Stacks']

    def stack_exists(self, stackname):
        ret = True
        try:
            stack = self.describe_stacks(stackname=stackname)
        except Exception as e:
            ret = False
        return ret

    def update_stack(self, stackname, parameters, dryrun, templatebody=None, templateurl=None):
        if dryrun:
            logger.warning("Dryrun requested not updateing stack: %s" % (stackname,))
            return None
        args = {'StackName': stackname, "Capabilities": ['CAPABILITY_IAM' ]}
        if parameters:
            args['Parameters'] = parameters
        if templatebody:
            args['TemplateBody'] = json.dumps(templatebody)
        elif templateurl:
            args['TemplateUrl'] = templateurl
        else:
            logger.error("No body or URL given for stack")
            raise ValueError
        resp = self.cloudformation_client.update_stack(**args)
        super(Cloudformation, self).query_information(query=resp)
        return resp['StackId']
