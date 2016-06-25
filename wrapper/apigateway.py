from misc.Logger import logger
from misc import Misc
from wrapper.wrapper_base import wrapper_base
from misc.DictDiffer import DictDiffer


class Apigateway(wrapper_base):
    def __init__(self, session, dryrun=False):
        '''
        This function creates the initial client and resource objects
        :param session: a boto3 session object for connecting to aws
        :return: a wrapper.Dynamodb object for running wrapper commands
        '''
        logger.debug("Starting apigateway wrapper")
        self.apigateway_client = session.client(service_name="apigateway")
        self.dryrun = dryrun
        logger.debug("Dryrun value is %s" % self.dryrun)

    def information_apigateway(self, name=None):
        """
        This function gathers information about all apigateways
        :param name: Only a specific apigateway should be returned
        :type name: basestring
        :return: A list of apigateway objects
        :rtype: list
        """
        logger.info("Gathering top objects")
        gws = self.get_rest_api()
        for gw in gws:
            if name:
                if gw['name'] != name:
                    continue
            logger.info("Iterating over %s" % gw['id'])
            resources = self.get_resource(restid=gw['id'])
            gw['resources'] = []
            for resource in resources:
                if 'resourceMethods' not in resource:
                    logger.info("No methods defined")
                    break
                for method in resource['resourceMethods']:
                    logger.info("Gathering information about method %s" % method)
                    method_data = self.get_method(restid=gw['id'], resourceid=resource['id'], method=method)
                    resource['resourceMethods'][method] = method_data
                gw['resources'].append(resource)
        return gws

    def get_rest_api(self, restid=None):
        """
        This function returns top level rest api object
        :param restid: if specific rest id should be returned only
        :type restid: basestring
        :return: a rest top level object
        """
        if restid:
            logger.info("Returning Single rest api")
            ret = [self.apigateway_client.get_rest_api(restApiId=restid)]
            super(Apigateway, self).query_information(query=ret)
        else:
            logger.info("Returning all rest api's")
            resp = self.apigateway_client.get_rest_apis()
            super(Apigateway, self).query_information(query=resp)
            ret = resp['items']
        return ret

    def get_resource(self, restid, resourceid=None):
        """
        This function returns a resource object
        :param restid: the id of the rest api object
        :type restid: basestring
        :param resourceid: id of a single resource object
        :type resourceid: basestring
        :return: the resource object requested
        """
        if resourceid:
            logger.info("Returning single resource object")
            ret = self.apigateway_client.get_resource(restApiId=restid, resourceId=resourceid)
            super(Apigateway, self).query_information(query=ret)
        else:
            logger.info("All resources should be returned for api")
            resp = self.apigateway_client.get_resources(restApiId=restid)
            super(Apigateway, self).query_information(query=resp)
            ret = resp['items']
        return ret

    def get_method(self, restid, resourceid, method):
        """
        This function returns a method object
        :param method: the method that is requested
        :type method: basestring
        :param restid: the id of the rest api object
        :type restid: basestring
        :param resourceid: id of a single resource object
        :type resourceid: basestring
        :return: None if not found, else the object
        """
        try:
            ret = self.apigateway_client.get_method(restApiId=restid, resourceId=resourceid, httpMethod=method)
            super(Apigateway, self).query_information(query=ret)
            logger.debug("We found the requested method")
        except Exception as e:
            # https://github.com/aws/aws-cli/issues/1620
            if e.response['Error']['Code'] == "NotFoundException":
                logger.warning("Method %s for resource %s does not exist" % (method, resourceid))
            else:
                logger.error("%s" % e, )
            ret = None
        return ret

    def get_method_response(self, restid, resourceid, method, statuscode):
        """
        This function returns a method response object
        :param method: the method that is requested
        :type method: basestring
        :param restid: the id of the rest api object
        :type restid: basestring
        :param resourceid: id of a single resource object
        :type resourceid: basestring
        :param statuscode: the statuscode requested
        :type statuscode: basestring
        :return: None if not found, else the object
        """
        try:
            ret = self.apigateway_client.get_method_response(restApiId=restid, resourceId=resourceid, httpMethod=method,
                                                             statusCode=statuscode)
            super(Apigateway, self).query_information(query=ret)
            logger.debug("We found the method response")
        except Exception as e:
            # https://github.com/aws/aws-cli/issues/1620
            if e.response['Error']['Code'] == "NotFoundException":
                logger.warning("Method response %s for resource %s does not exist" % (statuscode, resourceid))
            else:
                logger.error("%s" % e, )
            ret = None
        return ret

    def get_integration(self, restid, resourceid, method):
        """
        This function returns an integration object
        :param method: the method that is requested
        :type method: basestring
        :param restid: the id of the rest api object
        :type restid: basestring
        :param resourceid: id of a single resource object
        :type resourceid: basestring
        :return: None if not found, else the object
        """
        try:
            ret = self.apigateway_client.get_integration(restApiId=restid, resourceId=resourceid, httpMethod=method)
            super(Apigateway, self).query_information(query=ret)
            logger.debug("Found the integration object")
        except Exception as e:
            if e.response['Error']['Code'] == "NotFoundException":
                logger.warning("Method integration for %s method does not exist" % (method))
            else:
                logger.error("%s" % e, )
            ret = None
        return ret

    def get_integration_response(self, restid, resourceid, method, status):
        """
        This function returns an integration response object
        :param method: the method that is requested
        :type method: basestring
        :param restid: the id of the rest api object
        :type restid: basestring
        :param resourceid: id of a single resource object
        :type resourceid: basestring
        :param status: the statuscode that is quried
        :return: None if not found, else the object
        """
        try:
            ret = self.apigateway_client.get_integration_response(restApiId=restid, resourceId=resourceid,
                                                                  httpMethod=method, statusCode=status)
            super(Apigateway, self).query_information(query=ret)
            logger.debug("Found the integration response")
        except Exception as e:
            if e.response['Error']['Code'] == "NotFoundException":
                logger.warning("Method integration for %s method does not exist" % (method))
            else:
                logger.error("%s" % e, )
            ret = None
        return ret

    def apigateway_exists(self, name):
        """
        function checks if the apigateway exists or not
        :param name: name of the apigateway to test
        :type name: basestring
        :return: True if found, false if not
        :rtype: bool
        """
        gw_id = self.get_rest_api_by_name(name=name)
        if gw_id:
            ret = True
        else:
            ret = False
        logger.debug("The apigateway %s status: %s" % (name, ret))
        return ret

    def create_rest_api(self, name, desc):
        """
        This function creates a top level rest api
        :param name: name of the rest api to create
        :type name: basestring
        :param desc: The description of the rest api
        :type desc: basestring
        :return: The created rest api object
        :rtype: dict
        """
        if self.dryrun:
            logger.info("Dryrun requested no changes will be done")
            return None
        resp = self.apigateway_client.create_rest_api(name=name, description=desc)
        super(Apigateway, self).query_information(query=resp)
        logger.debug("The response of the created rest api: %s" % resp)
        return resp

    def create_method(self, restid, resourceid, method, authorizationtype, apikeyreq=False, further_opts=None):
        """
        This function creates a method object
        :param method: the method that is requested
        :type method: basestring
        :param restid: the id of the rest api object
        :type restid: basestring
        :param resourceid: id of a single resource object
        :type resourceid: basestring
        :param authorizationtype:
        :type authorizationtype: basestring
        :param apikeyreq: should apikey be required
        :type apikeyreq: bool
        :param further_opts: This opt passes in json_data fur not mandatory options
        :type further_opts: dict
        :return: the created method object
        """
        if self.dryrun:
            logger.info("Dryrun requested no changes will be done")
            return None
        if isinstance(apikeyreq, bool) is False:
            logger.debug("apikey is not boolean, converting")
            apikeyreq = Misc.str2bool(apikeyreq)
        opts = {'restApiId': restid, 'resourceId': resourceid, 'httpMethod': method,
                'authorizationType': authorizationtype, 'apiKeyRequired': apikeyreq}
        if 'requestParameters' in further_opts:
            opts['requestParameters'] = further_opts['requestParameters']
        if 'requestModels' in further_opts:
            opts['requestModels'] = further_opts['requestModels']
        logger.debug("The opts sent to create method %s" % opts)
        resp = self.apigateway_client.put_method(**opts)
        super(Apigateway, self).query_information(query=resp)
        return resp

    def create_method_response(self, restid, resourceid, method, statuscode, further_ops):
        """
        This function creates a method response
        :param method: the method that is requested
        :type method: basestring
        :param restid: the id of the rest api object
        :type restid: basestring
        :param resourceid: id of a single resource object
        :type resourceid: basestring
        :param statuscode: the status code
        :type statuscode: basestring
        :param further_opts: This opt passes in json_data fur not mandatory options
        :type further_opts: dict
        :return: the created method response object
        """
        if self.dryrun:
            logger.info("Dryrun requested no changes will be done")
            return None
        opts = {'restApiId': restid, 'resourceId': resourceid, 'httpMethod': method, 'statusCode': statuscode}
        if 'responseParameters' in further_ops:
            opts['responseParameters'] = further_ops['responseParameters']
        if 'responseModels' in further_ops:
            opts['responseModels'] = further_ops['responseModels']
        logger.debug("The opts sent to create method response %s" % opts)
        resp = self.apigateway_client.put_method_response(**opts)
        super(Apigateway, self).query_information(query=resp)
        return resp

    def create_integration_response(self, restid, resourceid, method, statuscode, further_opts=None):
        """
        This function creates an integration response object
        :param method: the method that is requested
        :type method: basestring
        :param restid: the id of the rest api object
        :type restid: basestring
        :param resourceid: id of a single resource object
        :type resourceid: basestring
        :param statuscode: thestatus code to attach integration response
        :type statuscode: basestring
        :param further_opts: This opt passes in json_data fur not mandatory options
        :type further_opts: dict
        :return:
        """
        if self.dryrun:
            logger.info("Dryrun requested no changes will be done")
            return None
        opts = {'restApiId': restid, 'resourceId': resourceid, 'httpMethod': method, 'statusCode': statuscode}
        for element in ['selectionPattern', 'responseParameters', 'responseTemplates']:
            if element in further_opts:
                if further_opts[element] == "None":
                    opts[element] = None
                else:
                    opts[element] = further_opts[element]
        logger.debug("The opts sent to create integration response %s" % opts)
        resp = self.apigateway_client.put_integration_response(**opts)
        super(Apigateway, self).query_information(query=resp)
        return resp

    def delete_method_response(self, restid, resourceid, method, statuscode):
        """
        This function deletes method response
        :param method: the method that is requested
        :type method: basestring
        :param restid: the id of the rest api object
        :type restid: basestring
        :param resourceid: id of a single resource object
        :type resourceid: basestring
        :param statuscode: the status code to find
        :type statuscode: basestring
        :return: None
        """
        if self.dryrun:
            logger.info("Dryrun requested no changes will be done")
            return None
        resp = self.apigateway_client.delete_method_response(restApiId=restid, resourceId=resourceid, httpMethod=method,
                                                             statusCode=statuscode)
        super(Apigateway, self).query_information(query=resp)
        return resp

    def update_method_response(self, restid, resourceid, method, statuscode, operation):
        """
        This function updates a method a response
        :param method: the method that is requested
        :type method: basestring
        :param restid: the id of the rest api object
        :type restid: basestring
        :param resourceid: id of a single resource object
        :type resourceid: basestring
        :param statuscode:the statuscode to update
        :type statuscode: basestring
        :param operation: an array of patchOperations
        :type operation: list[dict]
        :return: the obdated method response object
        """
        if self.dryrun:
            logger.info("Dryrun requested no changes will be done")
            return None
        resp = self.apigateway_client.update_method_response(restApiId=restid, resourceId=resourceid, httpMethod=method,
                                                             statusCode=statuscode, patchOperations=operation)
        super(Apigateway, self).query_information(query=resp)
        logger.debug("The response of the update method response: %s" % resp)
        return resp

    def create_integration(self, restid, resourceid, method, integration_type, further_opts=None):
        """
        This function creates an integration object
        :param method: the method that is requested
        :type method: basestring
        :param restid: the id of the rest api object
        :type restid: basestring
        :param resourceid: id of a single resource object
        :type resourceid: basestring
        :param integration_type: an enum of the integration type
        :type integration_type: basestring
        :param further_opts: This opt passes in json_data fur not mandatory options
        :type further_opts: dict
        :return: object of the created  integration
        """
        if self.dryrun:
            logger.info("Dryrun requested no changes will be done")
            return None
        opts = {'restApiId': restid, 'resourceId': resourceid, 'httpMethod': method, 'type': integration_type,
                'integrationHttpMethod': method}
        # There is aws cli bug and integrationHttpMethod also needs to be added. may change later
        #        opts = {'restApiId': restid, 'resourceId': resourceid, 'httpMethod': method, 'type': integration_type}
        for element in ['integrationHttpMethod', 'uri', 'credentials', 'requestParameters', 'requestTemplates',
                        'cacheNamespace', 'cacheNamespace']:
            if element in further_opts:
                opts[element] = further_opts[element]
        logger.debug("The opts for integration object creation: %s" % opts)
        resp = self.apigateway_client.put_integration(**opts)
        super(Apigateway, self).query_information(query=resp)
        return resp

    def get_rest_api_by_name(self, name):
        """
        This function returns a rest api by name
        :param name: the name of the reste api to return
        :type name: basestring
        :return: a rest api top level object
        :rtype: object
        """
        gws = self.get_rest_api()
        ret = None
        logger.debug("Searcing for rest api by name")
        for gw in gws:
            if gw['name'] == name:
                logger.info("Found the gw by name")
                ret = gw
        return ret

    def update_rest_api(self, restid, operation):
        """
        This function updates a rest api top level object
        :param restid: the id of the rest api object
        :type restid: basestring
        :param operation: a list of patchOperations
        :type operation: list
        :return: the updated rest api object
        :rtype: object
        """
        if self.dryrun:
            logger.info("Dryrun requested no changes will be done")
            return None
        resp = self.apigateway_client.update_rest_api(restApiId=restid, patchOperations=operation)
        super(Apigateway, self).query_information(query=resp)
        return resp

    def update_method(self, restid, resourceid, method, operation):
        """
        This function updates a method object
        :param method: the method that is requested
        :type method: basestring
        :param restid: the id of the rest api object
        :type restid: basestring
        :param resourceid: id of a single resource object
        :type resourceid: basestring
        :param operation: an list of patchOperations
        :type operation: list
        :return: the updated method object
        :rtype: object
        """
        if self.dryrun:
            logger.info("Dryrun requested no changes will be done")
            return None
        resp = self.apigateway_client.update_method(restApiId=restid, resourceId=resourceid, httpMethod=method,
                                                    operation=operation)
        super(Apigateway, self).query_information(query=resp)
        return resp

    def update_integration_response(self, restid, resourceid, method, statuscode, operation):
        """
        This function updates an integration response
        :param method: the method that is requested
        :type method: basestring
        :param restid: the id of the rest api object
        :type restid: basestring
        :param resourceid: id of a single resource object
        :type resourceid: basestring
        :param statuscode: the statuscode where the integration response is
        :type statuscode: basestring
        :param operation: a list of patchOperations
        :type operation: list
        :return: the updated integration response object
        """
        if self.dryrun:
            logger.info("Dryrun requested no changes will be done")
            return None
        resp = self.apigateway_client.update_integration_response(restApiId=restid, resourceId=resourceid,
                                                                  httpMethod=method, statusCode=statuscode,
                                                                  patchOperations=operation)
        super(Apigateway, self).query_information(query=resp)
        return resp

    def generate_resourcehash(self, restid):
        """
        This function collects and returns a hash with resource object and their ids.

        This is used to find any resources that should be deleted or added
        :param restid: the id of the rest api object
        :type restid: basestring
        :return: a dict with resource name with resource id-s
        :rtype: dict
        """
        resources = self.get_resource(restid=restid)
        ret = {}
        for resource in resources:
            ret[resource['path']] = resource['id']
        return ret

    def create_resource(self, restid, parentid, pathpart):
        """
        This function creates a resource object
        :param restid: the id of the rest api object
        :type restid: basestring
        :param parentid: the parent id of the created resource, should be rest api
        :type parentid: basestring
        :param pathpart: The pathpart where the resource be
        :type pathpart: basestring
        :return: the resource object created
        """
        if self.dryrun:
            logger.info("Dryrun requested no changes will be done")
            return None
        resp = self.apigateway_client.create_resource(restApiId=restid, parentId=parentid, pathPart=pathpart)
        super(Apigateway, self).query_information(query=resp)
        return resp

    def delete_resource(self, restid, resourceid):
        """
        This function deletes a resource object
        :param restid: the id of the rest api object
        :type restid: basestring
        :param resourceid: id of a single resource object
        :type resourceid: basestring
        :return: None
        """
        if self.dryrun:
            logger.info("Dryrun requested no changes will be done")
            return None
        resp = self.apigateway_client.delete_resource(restApiId=restid, resourceId=resourceid)
        super(Apigateway, self).query_information(query=resp)
        return resp

    def delete_integration_response(self, restid, resourceid, method, statuscode):
        """
        This function deletes an integration response
        :param method: the method that is requested
        :type method: basestring
        :param restid: the id of the rest api object
        :type restid: basestring
        :param resourceid: id of a single resource object
        :type resourceid: basestring
        :param statuscode: the statuscode to delete
        :type statuscode: basestring
        :return: None
        """
        if self.dryrun:
            logger.info("Dryrun requested no changes will be done")
            return None
        resp = self.apigateway_client.delete_integration_response(restApiId=restid, resourceId=resourceid,
                                                                  httpMethod=method, statusCode=statuscode)
        super(Apigateway, self).query_information(query=resp)
        return resp

    def method_exists(self, restid, resourceid, method):
        try:
            self.get_method(restid=restid, resourceid=resourceid, method=method)
            return True
        except:
            return False

    def method_response_exists(self, restid, resourceid, method, statuscode):
        try:
            self.get_method_response(restid=restid, resourceid=resourceid, method=method, statuscode=statuscode)
            return True
        except:
            return False

    def integration_response_exists(self, restid, resourceid, method, status):
        try:
            self.get_integration_response(restid=restid, resourceid=resourceid, method=method, status=status)
            return True
        except:
            return False

    def integration_exists(self, restid, resourceid, method):
        try:
            self.get_integration(restid=restid, resourceid=resourceid, method=method)
            return True
        except:
            return False

    def compare_method(self, restid, resourceid, method, json_data):
        """
        This function compares a json data to the current method to detect an updates that need to be done
        :param method: the method that is requested
        :type method: basestring
        :param restid: the id of the rest api object
        :type restid: basestring
        :param resourceid: id of a single resource object
        :type resourceid: basestring
        :param json_data: the json data from the model that is the representation of the current state
        :type json_data: dict
        :return: None
        """
        logger.info("Looking at restid: %s, resourceid: %s, and method: %s" % (restid, resourceid, method))
        # First we test if the top level method is created or we need to create it
        if not self.method_exists(restid=restid, resourceid=resourceid, method=method):
            logger.info("Need to create method: %s" % method)
            cur_method = self.create_method(restid=restid, resourceid=resourceid, method=method,
                                            authorizationtype=json_data['authorizationType'], further_opts=json_data)
        else:
            cur_method = self.get_method(restid=restid, resourceid=resourceid, method=method)
            logger.info("Method existed, need to compare for changes")
            for element in ['authorizationType', 'apiKeyRequired', 'requestParameters', 'requestModels']:
                if (element in json_data and element in cur_method) and json_data[element] != cur_method[element]:
                    logger.warning("Need to update %s" % element)
                    self.update_method(restid=restid, resourceid=resourceid, method=method, operation=[
                        {'op': 'replace', 'path': "/%s" % element, 'value': json_data[element]}])
                if element not in json_data:
                    logger.debug("Upload template missing key %s, skipping" % element)
                if element not in cur_method and element in json_data:
                    logger.warning("Not defined in current method need to update current method with %s" % element)
        # Check if method needs to be deleted
        if 'methodResponses' in cur_method:
            for statuscode in cur_method['methodResponses']:
                if statuscode not in json_data['methodResponses']:
                    logger.warning("This method response needs to be deleted %s" % statuscode)
                    self.delete_method_response(restid=restid, resourceid=resourceid, method=method,
                                                statuscode=statuscode)
        # iterate over status codes and check we need to create or update
        for statuscode in json_data['methodResponses']:
            if not self.method_response_exists(restid=restid, resourceid=resourceid, method=method,
                                               statuscode=statuscode):
                logger.debug("Creating method response %s" % statuscode)
                self.create_method_response(restid=restid, resourceid=resourceid, method=method, statuscode=statuscode,
                                            further_ops=json_data['methodResponses'][statuscode])
            else:
                cur_response = self.get_method_response(restid=restid, resourceid=resourceid, method=method,
                                                        statuscode=statuscode)
                logger.debug("Need to compare the responses")
                dictdiffer = DictDiffer(cur_response, json_data['methodResponses'][statuscode])
                for remove_statuscode in dictdiffer.added():
                    logger.info("Need to remove statuscode: %s" % remove_statuscode)
                    self.delete_method_response(restid=restid, resourceid=resourceid, method=method,
                                                statuscode=remove_statuscode)
                for add_statuscode in dictdiffer.removed():
                    logger.info("Need to add statuscode: %s" % add_statuscode)
                    self.create_method_response(restid=restid, resourceid=resourceid, method=method,
                                                statuscode=add_statuscode,
                                                further_ops=json_data['methodResponses'][add_statuscode])
                for changed_statuscode in dictdiffer.changed():
                    logger.info("Need to update statuscode: %s" % changed_statuscode)
                    cur_method_statuscode = cur_method['methodResponses'][changed_statuscode]
                    json_data_statuscode = json_data['methodmethod']['methodResponses'][changed_statuscode]
                    for element in ['responseParameters', 'responseTemplates']:
                        if element not in json_data_statuscode:
                            continue
                        change_dictdiffer = DictDiffer(
                            cur_method_statuscode[element],
                            json_data_statuscode[element])
                        for add_int_statuscode in change_dictdiffer.removed():
                            logger.info("method response is missing, adding: %s" % add_int_statuscode)
                            self.update_method_response(restid=restid, resourceid=resourceid, method=method,
                                                        statuscode=changed_statuscode, operation=[
                                    {'op': 'add', 'path': "/%s/%s" % (element, add_int_statuscode), 'value':
                                        json_data_statuscode[element][add_int_statuscode]}])
                        for remove_int_statuscode in change_dictdiffer.added():
                            logger.info("Method response is present, deleting: %s" % remove_int_statuscode)
                            self.update_method_response(restid=restid, resourceid=resourceid, method=method,
                                                        statuscode=changed_statuscode, operation=[
                                    {'op': 'remove', 'path': "/%s/%s" % (element, remove_int_statuscode)}])
                        for change_int_statuscode in change_dictdiffer.changed():
                            logger.info("There is a change in value, need to update: %s" % change_int_statuscode)
                            self.update_method_response(restid=restid, resourceid=resourceid, method=method,
                                                        statuscode=changed_statuscode, operation=[
                                    {'op': 'replace', 'path': "/%s/%s" % (element, change_int_statuscode), 'value':
                                        json_data_statuscode[element][change_int_statuscode]}])
        # method integration
        if self.integration_exists(restid=restid, resourceid=resourceid, method=method):
            cur_method_integration = self.get_integration(restid=restid, resourceid=resourceid, method=method)
            dictdiffer_integration_response = DictDiffer(cur_method_integration['integrationResponses'],
                                                         json_data['methodIntegration']['integrationResponses'])
            for remove_response in dictdiffer_integration_response.added():
                logger.info("Need to remove integration response: %s" % remove_response)
                self.delete_integration_response(restid=restid, resourceid=resourceid, method=method,
                                                 statuscode=remove_response)
            for add_response in dictdiffer_integration_response.removed():
                logger.info("Need to add integration response: %s" % add_response)
                self.create_integration_response(restid=restid, resourceid=resourceid, method=method,
                                                 statuscode=add_response,
                                                 further_opts=json_data['methodIntegration']['integrationResponses'][
                                                     add_response])
            for changed_response in dictdiffer_integration_response.changed():
                logger.info("Need to change response value: %s" % changed_response)
                cur_method_integration_response = cur_method_integration['integrationResponses'][changed_response]
                json_data_integration_response = json_data['methodIntegration']['integrationResponses'][
                    changed_response]
                if 'selectionPattern' in cur_method_integration_response:
                    if (cur_method_integration_response['selectionPattern'] !=
                            json_data_integration_response['selectionPattern']):
                        logger.debug("selectionPattern needs to be updated")
                        self.update_integration_response(restid=restid, resourceid=resourceid, method=method,
                                                         statuscode=changed_response, operation=[
                                {'op': 'replace', 'path': '/selectionPattern',
                                 'value': json_data_integration_response['selectionPattern']}])
                for element in ['responseParameters', 'responseTemplates']:
                    if element not in json_data_integration_response:
                        continue
                    change_dictdiffer = DictDiffer(
                        cur_method_integration_response[element],
                        json_data_integration_response[element])
                    for add_int_response in change_dictdiffer.removed():
                        logger.debug("Need to add the integration response: %s" % add_int_response)
                        self.update_integration_response(restid=restid, resourceid=resourceid, method=method,
                                                         statuscode=changed_response, operation=[
                                {'op': 'add', 'path': "/%s/%s" % (element, add_int_response), 'value':
                                    json_data_integration_response[element][add_int_response]}])
                    for remove_int_response in change_dictdiffer.added():
                        logger.debug("Need to remove the integration response: %s" % remove_int_response)
                        self.update_integration_response(restid=restid, resourceid=resourceid, method=method,
                                                         statuscode=changed_response, operation=[
                                {'op': 'remove', 'path': "/%s/%s" % (element, remove_int_response)}])
                    for change_int_response in change_dictdiffer.changed():
                        logger.debug("Need to update the integration response: %s" % change_int_response)
                        self.update_integration_response(restid=restid, resourceid=resourceid, method=method,
                                                         statuscode=changed_response, operation=[
                                {'op': 'replace', 'path': "/%s/%s" % (element, change_int_response), 'value':
                                    json_data_integration_response[element][change_int_response]}])
        else:
            logger.debug("Need to create method integration")
            cur_method_integration = self.create_integration(restid=restid, resourceid=resourceid, method=method,
                                                             integration_type=json_data['methodIntegration'][
                                                                 'type'],
                                                             further_opts=json_data['methodIntegration'])
            for integration_response in json_data['methodIntegration']['integrationResponses']:
                logger.debug("Need to create the method integrations for the new method")
                self.create_integration_response(restid=restid, resourceid=resourceid, method=method,
                                                 statuscode=integration_response,
                                                 further_opts=
                                                 json_data['methodIntegration']['integrationResponses'][
                                                     integration_response])
        logger.info("Done with updates")
        return None

    def delete_rest_api(self, restid):
        if self.dryrun:
            logger.info("Dryrun requested no changes will be done")
            return None
        resp = self.apigateway_client.delete_rest_api(restApiId=restid)
        super(Apigateway, self).query_information(query=resp)
        return resp

    def rest_api_exists(self, name):
        try:
            self.get_rest_api_by_name(name=name)
            return True
        except Exception as e:
            if e.response['Error']['Code'] == "NotFoundException":
                return False
            else:
                logger.error(e)
                exit(1)

    def create_deployment(self, restid, stagename, stagedesc, desc, cacheclusterenabled, cacheclustersize=None):
        if self.dryrun:
            logger.info("Dryrun requested no changes will be done")
            return None
        args = {'restApiId': restid, 'stageName': stagename, 'stageDescription': stagedesc, 'description': desc}
        if cacheclusterenabled:
            args.update({'cacheClusterEnabled': cacheclusterenabled, 'cacheClusterSize': cacheclustersize})
        else:
            args['cacheClusterEnabled'] = cacheclusterenabled
        resp = self.apigateway_client.create_deployment(**args)
        super(Apigateway, self).query_information(query=resp)
        return resp

    def delete_deployment(self, restid, deploymentid):
        if self.dryrun:
            logger.info("Dryrun requested no changes will be done")
            return None
        ret = self.apigateway_client.delete_deployment(restApiId=restid, deploymentId=deploymentid)
        super(Apigateway, self).query_information(query=ret)
        return ret

    def get_deployments(self, restid, deploymentid=None):
        if deploymentid:
            resp = self.apigateway_client.get_deployment(restApiId=restid, deploymentId=deploymentid)
            super(Apigateway, self).query_information(query=resp)
            ret = [resp]
        else:
            resp = self.apigateway_client.get_deployments(restApiId=restid)
            super(Apigateway, self).query_information(query=resp)
            ret = resp['items']
        return ret

    def put_rest_api(self, restid, parameters, body, mode="overwrite", failonwarnings=True):
        if self.dryrun:
            logger.info("Dryrun requested no changes will be done")
            return None
        args = {'restApiId': restid, 'body': body, 'mode': mode, 'failOnWarnings': failonwarnings}
        if parameters:
            args['parameters'] = parameters
        resp = self.apigateway_client.put_rest_api(**args)
        super(Apigateway, self).query_information(query=resp)
        return resp

    def import_rest_api(self, restid, parameters, body):
        if self.dryrun:
            logger.info("Dryrun requested no changes will be done")
            return None
        args = {'restApiId': restid, 'body': body}
        if parameters:
            args['parameters'] = parameters
        resp = self.apigateway_client.import_rest_api(**args)
        super(Apigateway, self).query_information(query=resp)
        return resp
