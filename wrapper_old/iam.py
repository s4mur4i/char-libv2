import boto3

from misc.Logger import logger
from misc import Misc
from wrapper.vpc import Vpc


class Iam(object):
    def __init__(self, region='us-east-1'):
        logger.debug("Starting EC2Class for iam")
        self.iam = boto3.client('iam', region_name=region)
        self.resource = boto3.resource('iam', region_name=region)
        self.region = region

    def get_server_certs(self):
        certs = self.iam.list_server_certificates()
        return certs['ServerCertificateMetadataList']

    def get_server_cert_for_env(self, env=None):
        certs = self.get_server_certs()
        v = Vpc()
        vpc = v.get_vpc_from_env(env=env)
        domain = Misc.get_value_from_array_hash(dictlist=vpc['Tags'], key='Domain')
        cert_name = "star." + domain
        logger.debug("Searching for cert domain %s" % cert_name, )
        for c in certs:
            logger.debug("Investigateing Cert %s" % c, )
            if c['ServerCertificateName'] == cert_name:
                logger.debug("We found the server certificate we are looking for")
                return c
        logger.warning("Could not find the certificate for %s" % env, )
        return None

    def delete_server_certs(self, cert_name=None):
        ret = self.iam.delete_server_certificate(ServerCertificateName=cert_name)
        return ret

    def upload_server_cert(self, cert_name=None, pub_key=None, priv_key=None, cert_chain=None):
        if cert_chain:
            ret = self.iam.upload_server_certificate(Path="/", ServerCertificateName=cert_name, CertificateBody=pub_key,
                                                     PrivateKey=priv_key, CertificateChain=cert_chain)
        else:
            ret = self.iam.upload_server_certificate(Path="/", ServerCertificateName=cert_name, CertificateBody=pub_key,
                                                     PrivateKey=priv_key)
        return ret

    def get_server_cert(self, name=None):
        cert = self.iam.get_server_certificate(ServerCertificateName=name)
        logger.debug("Got Server cert: %s" % cert['ServerCertificate'], )
        return cert['ServerCertificate']

    def update_server_cert(self, cert_name=None, new_name=None):
        ret = self.iam.update_server_certificate(ServerCertificateName=cert_name, NewServerCertificateName=new_name)
        logger.debug("Ret value of update_server_cert %s" % ret, )
        return ret

    def list_policies(self, scope="All", onlyattached=False, ):
        resp = self.iam.list_policies(Scope=scope, OnlyAttached=onlyattached, MaxItems=1000)
        return resp['Policies']

    def get_policy(self, arn=None):
        try:
            resp = self.iam.get_policy(PolicyArn=arn)
        except Exception as e:
            if "An error occurred (NoSuchEntity) when calling the GetPolicy operation" in e:
                logger.warning("Policy does not exist %s" % arn, )
            else:
                logger.error("%s" % e, )
            return None
        return resp['Policy']

    def create_policy(self, name, statement, description, dryrun, path="/"):
        if dryrun:
            logger.warning("Dryrun requested, not creating %s resource: %s" % (name, str(statement)))
            return None
        document = {'Version': '2012-10-17', 'Statement': statement}
        document = Misc.convert_to_json(document)
        print document
        resp = self.iam.create_policy(PolicyName=name, Path=path, PolicyDocument=document, Description=description)
        return resp['Policy']

    def get_policy_version(self, arn, version):
        resp = self.iam.get_policy_version(PolicyArn=arn, VersionId=version)
        return resp['PolicyVersion']

    def get_policy_versions(self, arn):
        resp = self.iam.list_policy_versions(PolicyArn=arn)
        return resp['Versions']

    def remove_older_policy_versions(self, arn, dryrun):
        default_version = self.get_policy(arn=arn)['DefaultVersionId']
        versions = self.get_policy_versions(arn=arn)
        versions = [i for i in versions if i['VersionId'] != default_version]
        for v in versions:
            logger.debug("Going to delete policy version %s" % (v['VersionId'],))
            self.delete_policy_version(arn=arn, version=v['VersionId'], dryrun=dryrun)

    def delete_policy_version(self, arn, version, dryrun):
        if dryrun:
            logger.warning("Dryrun requested for deleting policy %s version: %s" % (arn, version))
            return None
        resp = self.iam.delete_policy_version(PolicyArn=arn, VersionId=version)
        return resp

    def create_policy_version(self, arn, statement, dryrun, setasdefault=True):
        if dryrun:
            logger.warning("Dryrun requested for creating policy version %s" % (arn,))
            return None
        document = {'Version': '2012-10-17', 'Statement': statement}
        document = Misc.convert_to_json(document)
        resp = self.iam.create_policy_version(PolicyArn=arn, PolicyDocument=document, SetAsDefault=setasdefault)
        return resp['PolicyVersion']

    def get_user_policies(self, username, path="/"):
        resp = self.iam.list_attached_user_policies(UserName=username, PathPrefix=path)
        return resp['AttachedPolicies']

    def attach_policy_to_user(self, username, policyarn, dryrun):
        if dryrun:
            logger.warning("Dryrun requested for attaching policy %s to user %s" % (policyarn, username))
            return None
        resp = self.iam.attach_user_policy(UserName=username, PolicyArn=policyarn)
        return resp

    def detach_policy_from_user(self, username, policyarn, dryrun):
        if dryrun:
            logger.warning("Dryrun requested for detaching policy %s from user %s" % (policyarn, username))
            return None
        resp = self.iam.detach_user_policy(UserName=username, PolicyArn=policyarn)
        return resp

    def create_user_credentials(self, username=None, dryrun=None):
        if dryrun:
            logger.warning("Dryrun requested for creation of user credentials for %s" % (username))
            return None
        resp = self.iam.create_access_key(UserName=username)
        return resp['AccessKey']

    def list_user_credentials(self, username):
        resp = self.iam.list_access_keys(UserName=username)
        return resp['AccessKeyMetadata']

    def get_access_key_last_used(self, access_key):
        resp = self.iam.get_access_key_last_used(AccessKeyId=access_key)
        if 'LastUsedDate' not in resp['AccessKeyLastUsed']:
            resp['AccessKeyLastUsed']['LastUsedDate'] = None
        return resp['AccessKeyLastUsed']
