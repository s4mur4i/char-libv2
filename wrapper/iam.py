from misc.Logger import logger
from misc import Misc
from wrapper.wrapper_base import wrapper_base
import json

class Iam(wrapper_base):
    def __init__(self, session):
        '''
        This function creates the initial client and resource objects
        :param session: a boto3 session object for connecting to aws
        :return: a wrapper.Iam object for running wrapper commands
        '''
        logger.debug("Starting iam wrapper")
        self.iam_client = session.client(service_name="iam")
        self.iam_resource = session.resource(service_name="iam")

    def get_user(self, username=None):
        """
        This function retrieves a user object or returns current user
        :param username: The username that should only be returned
        :return: A list of boto3 user objects
        """
        if username:
            response = self.iam_client.get_user(UserName=username)
        else:
            response = self.iam_client.get_user()
        super(Iam, self).query_information(query=response)
        return response['User']

    def get_account_id(self):
        """
        This functions extracts the AWS account id from the user object
        :return: the AWs account id
        :rtype: int
        """
        user_data = self.get_user()
        if 'Arn' in user_data:
            arn = user_data['Arn']
            ret = Misc.parse_arn(arn=arn)['account-id']
        else:
            logger.error("Can not determine the Account ID, User has no ARN")
            raise ValueError
        return ret

    def create_iam_user(self, username, dryrun, path="/"):
        """
        This function creates an iam user
        :param username: The requeted username for the usre
        :param dryrun: No changes should be done
        :param path: The pathin IAM to create the user
        :return: a boto3.user object with the created user details
        """
        if dryrun:
            logger.warning("Dryrun requested for creating user %s" % (username,))
            return None
        resp = self.iam_client.create_user(Path=path, UserName=username)
        super(Iam, self).query_information(query=resp)
        return resp['User']

    def iam_user_exists(self, username):
        """
        This function tests if a user already exists
        :param username: the username that should be teted
        :return: True or false, if user exists
        """
        ret = True
        try:
            resp = self.iam_client.get_user(UserName=username)
            super(Iam, self).query_information(query=resp)
        except Exception:
            ret = False
        return ret

    def list_user_groups(self, username):
        """
        This function returns all groups attached to users
        :param username: The specific user whoes group should be returned
        :return: a list of user with groups
        """
        usernames = []
        if username:
            usernames.append(username)
        else:
            users = self.list_iam_users()
            for user in users:
                usernames.append(user['UserName'])
        ret = {}
        for user in usernames:
            resp = self.iam_client.list_groups_for_user(UserName=user)
            super(Iam, self).query_information(query=resp)
            ret[user] = []
            for group in resp['Groups']:
                ret[user].append(group['GroupName'])
        return ret

    def list_iam_users(self):
        """
        This function returns all iam users
        :return: list of boto3 iam users
        """
        ret = self.iam_client.list_users()
        super(Iam, self).query_information(query=ret)
        for r in ret['Users']:
            if 'PasswordLastUsed' not in r:
                # Users without password will not return empty element, need to add.
                r['PasswordLastUsed'] = None
        return ret['Users']

    def list_groups(self):
        """
        This function returns a list of groups i aws
        :return: a list of boto3.groups
        """
        ret = self.iam_resource.list_groups()
        super(Iam, self).query_information(query=ret)
        return ret['Groups']

    def add_iam_user_to_group(self, username, groupname):
        """
        This function adds a user to a group
        :param username: The username that should be added
        :param groupname: The groupname tat the use should be added
        :return: Nothing
        """
        ret = self.iam_client.add_user_to_group(GroupName=groupname, UserName=username)
        super(Iam, self).query_information(query=ret)
        return ret

    def create_iam_login_profile(self, username, password, passwordreset=True):
        """
        This function create a login profile for the user
        :param username: The username that should get the login profile
        :param password: The temporary password for the user
        :param passwordreset: After login should the user reset their password
        :return: Information about the created loginprofile
        """
        ret = self.iam_client.create_login_profile(UserName=username, Password=password,
                                                   PasswordResetRequired=passwordreset)
        super(Iam, self).query_information(query=ret)
        return ret['LoginProfile']

    def get_login_profile(self, username):
        """
        This function retrieves information about a users login_porfile
        Can be used to test if the user has a login profile or not
        :param username: The username that should be retrieved
        :return: a login profile object, or None if no profile exists
        """
        try:
            ret = self.iam_client.get_login_profile(UserName=username)
            super(Iam, self).query_information(query=ret)
        except Exception:
            ret = None
        return ret

    def get_role(self,name):
        """
        This function returns an iam role
        :param name:
        :return:
        """
        ret = self.iam_client.get_role(RoleName=name)
        super(Iam, self).query_information(query=ret)
        return ret

    def iam_role_exists(self, name):
        """
        This function tests if iam role exists
        :param name:
        :return:
        """
        try:
            self.get_role(name=name)
            return True
        except Exception as e:
            if e.response['Error']['Code'] == "NoSuchEntity":
                return False
            else:
                logger.error(e)
                exit(1)

    def create_iam(self, name, assume_document):
        """
        This function create an iam role
        :param name:
        :param assume_document:
        :return:
        """
        try:
            role = self.iam_client.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(assume_document))
            super(Iam, self).query_information(query=role)
            return role
        except Exception as e:
            logger.error("Exception: %s" % e)

    def delete_iam(self, name):
        """
        This function deletes an iam role
        :param name:
        :return:
        """
        ret = self.iam_resource.Role(name).delete()
        super(Iam, self).query_information(query=ret)
        return ret

    def delete_iam_inline_policy(self, role_name,policy_name):
        """
        This function deletes an inline policy
        :param role_name:
        :param policy_name:
        :return:
        """
        ret = self.iam_resource.RolePolicy(role_name,policy_name).delete()
        super(Iam, self).query_information(query=ret)
        return ret

    def update_role_policy(self, role_name, policy_name, policy_document):
        """
        This function updates a role policy
        :param role_name:
        :param policy_name:
        :param policy_document:
        :return:
        """
        try:
            ret =  self.iam_client.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_document)
            super(Iam, self).query_information(query=ret)
            return ret
        except Exception as e:
            logger.error("Exception: %s" % e)
