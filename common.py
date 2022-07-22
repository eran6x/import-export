"""
common classes for all scripts
==============================

Author: Elad Elkes (June-22)
 This script is used to import and export policies from source to target fsm. It usesDLP policy management REST API
 to pull policy configuration from source FSM and create including rules, classifiers,

 the policy management apis currently support:
 rule condition, thresholds, severity and action, source and destination including protected channels and resources,
 and rule exceptions, custom policies and custom classifiers. both DLP and Discovery policies are supported.


 Currently (June-22) there are 10 APIs dedicated for policy management:
 1. GET /dlp/rest/v1/policy/enabled-names?type={policy_type}
 2. GET /dlp/rest/v1/policy/rules?policyName={policy_name}
 3. GET /dlp/rest/v1/policy/rules/severity-action?policyName={policy_name}
 4. GET dlp/rest/v1/policy/rules/source-destination?policyName={policy_name}
 5. GET /dlp/rest/v1/policy/rules/exceptions?type={policy_type}
 6. GET dlp/rest/v1/policy/rules/exceptions?type={policy_type}&ruleName={rule_name}
 7. POST dlp/rest/v1/policy/rules
 8. POST /dlp/rest/v1/policy/rules/severity-action
 9. POST /dlp/rest/v1/policy/rules/source-destination
 10.POST /dlp/rest/v1/policy/rules/exceptions


 There are 3 classes: "Auth" class used to authenticate with the FSM and get JWT to perform the API calls.
 "GetPolicies" class used to send GET requests for the policies, "PostPolicies" class used to send POST requests and
 create or update DLP and Discovery policies.

 the script pulls a list of enabled policies,then iterate on every policy to GET the data from source FSM and POST
 the data to the target FSM. source and target fsm credentials and address are hard coded at the moment under
 the main function and the plan is to read them from cli.

Updated: 

Modified version: export_policies_to_file_cli
Author: Eran Amir (July-22) 
Modified @Elad's version to seperate import and export policies to files.

"""

import json
import logging
import time
import requests
import urllib3
import os
from os import path


# suppress ssl warning message
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Auth:
    """ Create Authentication tokens"""

    def __init__(self, logger):
        """ init self"""
        self.logger = logger

    # get a token from fsm
    def get_access_token(self, fsm_server, user_name, user_password):
        """ get access tokens for credentials"""

        self.logger.info("Requesting access token from: " + fsm_server)
        # build the request
        url = f'https://{fsm_server}:9443/dlp/rest/v1/auth/refresh-token'
        headers = {'username': f'{user_name}', 'password': f'{user_password}'}
        try:
            # send the request and get the access token
            r = requests.post(url, headers=headers, verify=False)
            data = r.text
            json_data = json.loads(data)
            ref_token = json_data['access_token']

            self.logger.info("Successfully received token from: " + fsm_server)
            self.logger.info("The token is: " + ref_token)
            print('Successfully received a token from: ' + fsm_server)
            return ref_token

        except Exception:
            data = r.text
            print(data)
            print(r.status_code)
            self.logger.error("Failed to get a token from FSM: " + fsm_server)
            self.logger.error(data)
            print('\nFailed to get a token from: '
                  + fsm_server + ' ,please make sure the application user and password are correct.')
            exit()

# end Auth

class GetPolicies:
    """ Retrieve policies and policies attributes from FSM server """
    def __init__(self, logger):
        self.logger = logger

    def get_policy_list(self, source_token, source_fsm_server, policy_type):
        """ First task is to get a list of all the policies availble"""

        # build the request to get list of enabled policies
        try:
            url = f'https://{source_fsm_server}:9443/dlp/rest/v1/policy/enabled-names?type={policy_type}'
            headers = {'Authorization': f'Bearer {source_token}', 'Content-Type': 'application/json'}

            # send api request to get a list of enabled policies by name
            self.logger.info("Sending a request to get list of enabled policies")
            r = requests.get(url, headers=headers, verify=False)
            res = r.text
            res = res.replace('\n',"")
            self.logger.info(" Response is" + res)
            policies_response = json.loads(res)
            return policies_response

        except requests.exceptions.Timeout:
            self.logger.error("Timeout request for policy")
            exit()
        except:
            print("Failed to send the request to get list of enabled policies to: " + url)
            exit()


    # URL encode the policy name
    def get_policy_details(self, source_token, source_fsm_server, policy_name, request_type):
        """ Retrieve Policy attributes from FSM
            use request_type for URL manipulation
         """
        # build the request
        #policy_name_encoded = urllib3.parse.quote(policy_name)   TODO test if we need to encode for policy name with spaces and remove if not. 
        #url = f'https://{source_fsm_server}:9443/dlp/rest/v1/policy/rules{request_type}?policyName={policy_name_encoded}'
        url = f'https://{source_fsm_server}:9443/dlp/rest/v1/policy/rules{request_type}?policyName={policy_name}'

        headers = {'Authorization': f'Bearer {source_token}', 'Content-Type': 'application/json'}
        self.logger.info('GET rules and classifiers from: ' + source_fsm_server + ', policy:' + policy_name + "+" + request_type)
        try:
          # send api request to get the rules and classifiers
            r = requests.get(url, headers=headers, verify=False)
        except requests.exceptions.Timeout:
            self.logger.error("Timeout request for policy")
        except Exception as ex:
            print('Failed to GET policy:' + policy_name + "+" + request_type)
            print(r)
            self.logger.error(repr(ex))
            return {} #empty dictionary

        res = r.text
        if (r.status_code > 200): # something bad happened
            #res = res.replace('\n',"")
            self.logger.info("Response is:" + res)
            print('Failed to GET policy:' + policy_name)
            print("Request returned with HTTP code" + str(r.status_code))
            return {}

        policies_response = json.loads(res)
        json_format_rules_classifiers = json.dumps(policies_response, indent=4)
        return json_format_rules_classifiers
        # TODO: should retgurn the policy as JSON in dictionary format - why are we getting a string?


# Old GET requestssss TODO: redirect to the new policy

    def get_rules_classifiers___old_version(self, source_token, source_fsm_server, policy_name):

        # build the request
        url = f'https://{source_fsm_server}:9443/dlp/rest/v1/policy/rules?policyName={policy_name}'
        headers = {'Authorization': f'Bearer {source_token}', 'Content-Type': 'application/json'}
        print('GET rules and classifiers from: ' + source_fsm_server + ', policy:' + policy_name)
        try:
          # send api request to get the rules and classifiers
            r = requests.get(url, headers=headers, verify=False)
            res = r.text
            self.logger.info("\nRaw Response is" + res)
         
            policies_response = json.loads(res)
            json_format_rules_classifiers = json.dumps(policies_response, indent=4)
            return json_format_rules_classifiers
        except Exception:
            print(res)
            return {}


    def get_rules_classifiers(self, source_token, source_fsm_server, policy_name):
        """ get the policy definition, classifiers and conditions"""
        rules_classifiers_dict = GetPolicies.get_policy_details(self, source_token, source_fsm_server, policy_name, "")
        return rules_classifiers_dict


    def get_severity_action(self, source_token, source_fsm_server, policy_name):
        """ get the policy severity and action plan """
        sev_action_dict = GetPolicies.get_policy_details(self, source_token, source_fsm_server, policy_name, "/severity-action")
        return sev_action_dict


    def get_source_destination(self, source_token, source_fsm_server, policy_name):
        """ get the policy source and destination - for DLP but not discovery policies """
        src_dst_dict = GetPolicies.get_policy_details(self, source_token, source_fsm_server, policy_name, "/source-destination")
        return src_dst_dict

    def get_severity_action__old(self, source_token, source_fsm_server, policy_name):

        # build the request
        url = f'https://{source_fsm_server}:9443/dlp/rest/v1/policy/rules/severity-action?policyName={policy_name}'
        headers = {'Authorization': f'Bearer {source_token}', 'Content-Type': 'application/json'}

        # send the api request to get rules severity and action
        print('GET rule severity and action from: ' + source_fsm_server + ', policy:' + policy_name)
        try:        
            r = requests.get(url, headers=headers, verify=False)
            res = r.text
            self.logger.info("Raw Response is" + res)
            policies_response = json.loads(res)
            json_format_sev_action = json.dumps(policies_response, indent=4)
            return json_format_sev_action
        except Exception:
            print('Failed to GET policy:' + policy_name)
            print(res)
            return {}            

    def get_source_destination___old(self, source_token, source_fsm_server, policy_name):

        # build the request
        url = f'https://{source_fsm_server}:9443/dlp/rest/v1/policy/rules/source-destination?policyName={policy_name}'
        headers = {'Authorization': f'Bearer {source_token}', 'Content-Type': 'application/json'}

        # send the api request to get source and destination
        print('GET rule source and destination from: ' + source_fsm_server + ', policy:' + policy_name)
        try:        
            r = requests.get(url, headers=headers, verify=False)
            res = r.text
            self.logger.info("Raw Response is" + res)
            policies_response = json.loads(res)
            json_format_source_destination = json.dumps(policies_response, indent=4)
            return json_format_source_destination
        except Exception:
            print('Failed to GET policy:' + policy_name)
            print("Request returned with HTTP code" + str(r.status_code))
            return {}   

    def get_all_exceptions(self, source_token, source_fsm_server, policy_type):

        try:
            # build the post request to get list of rule exceptions
            url = f'https://{source_fsm_server}:9443/dlp/rest/v1/policy/rules/exceptions/all?type={policy_type}'
            headers = {'Authorization': f'Bearer {source_token}', 'Content-Type': 'application/json'}

            # send the api request to get the list of rule exceptions
            r = requests.get(url, headers=headers, verify=False)
            res = r.text
            exceptions_response = json.loads(res)
            # json_format_all_exceptions = json.dumps(policies_response, indent=4)
            return exceptions_response
        except Exception:
            exception_response = {}
            print('No rule exceptions found on ' + source_fsm_server)
            return exception_response
            pass

    def get_rule_exception(self, source_token, source_fsm_server, policy_type, rule_name):

        # build the post request to get rule exceptions
        url = f'https://{source_fsm_server}:9443/dlp/rest/v1/policy/rules/exceptions/?type={policy_type}&ruleName={rule_name}'
        headers = {'Authorization': f'Bearer {source_token}', 'Content-Type': 'application/json'}

        # send the api request to get rule exceptions
        print('GET rule exception from ' + policy_type + ' rule: ' + rule_name)
        r = requests.get(url, headers=headers, verify=False)
        res = r.text
        policies_response = json.loads(res)
        json_format_rule_exceptions = json.dumps(policies_response, indent=4)
        # print(json_format_rule_exceptions)
        return json_format_rule_exceptions
#end GetPolicies

####
#  Get Policies and rules from exported JSON files. 
#  Added to allow the import policies part to run independently of access the source FSM.
# Author: Eran Amir
# Date: July 22
####
class GetPoliciesFromFile:

    def __init__(self, logger):
        self.logger = logger

    ####
    # Load local file 
    # @param - filename
    # @return - JSON/dict
    ####
    def load_file_from_disk(logger, file_name):
        """ Generic function to load policy as JSON file and return the string"""
# TODO: make relative path wotk for any OS
        logger.info("Loading file:" + file_name)
        #script_dir = os.path.dirname(__file__) #<-- absolute dir the script is in
        abs_file_path = os.path.join(os.path.dirname(__file__),"json", file_name)         
        try:
            with open(abs_file_path) as list_file:
                #check for empty file 
                if os.path.getsize(abs_file_path) == 0:
                    return dict()
                response = json.load(list_file)
                logger.info(response)
            return response
        except Exception as ex:
            print("Failed to load file: " + abs_file_path + "\n" + repr(ex))
            logger.error("Failed to load file: " + abs_file_path + "\n" + repr(ex))
            exit()

    # get list of enabled policies
    def get_policy_list(logger, policy_type):
        policies_response = GetPoliciesFromFile.load_file_from_disk(logger, "enabled_policies.json")
        return policies_response


    def get_all_exceptions(logger, policy_type):
        ex_response = GetPoliciesFromFile.load_file_from_disk(logger, "exceptions.json")
        return ex_response


    def get_rules_classifiers(logger, policy_name):

        policy_filename = policy_name + "_rules_classifiers.json"
        logger.info('Import rules and classifiers for: ' + policy_name + ' from file: ' + policy_filename)
        response = GetPoliciesFromFile.load_file_from_disk(logger, policy_filename)
        return response

    def get_severity_action(logger, policy_name):

        policy_filename = policy_name + "_sev_action.json"
        logger.info('Import severity and action for: ' + policy_name + ' from file: ' + policy_filename)
        response = GetPoliciesFromFile.load_file_from_disk(logger, policy_filename)
        return response

    def get_source_destination(logger, policy_name):

        policy_filename = policy_name + "_source_destination.json"
        logger.info('Import source and destination for: ' + policy_name + ' from file: ' + policy_filename)
        response = GetPoliciesFromFile.load_file_from_disk(logger, policy_filename)
        return response

    def get_rule_exception(logger, policy_name):

        policy_filename = policy_name + "_exception.json"
        logger.info('Import source and destination for: ' + policy_name + ' from file:' + policy_filename)
        response = GetPoliciesFromFile.load_file_from_disk(logger, policy_filename)
        return response
#end GetPoliciesFromFile

#TODO: consolidate all the post methods into one.
class PostPolicies:
    """ Push Policies to FSM with RestAPI requests"""

    def __init__(self, logger):
        self.logger = logger

    def post_rules_classifiers(logger,target_token, target_fsm_server, rules_classifiers_output, policy_name):
        # post the input of: /dlp/rest/v1/policy/rules?policyName=
        logger.info('Push rules and classifiers to: ' + target_fsm_server + ' policy: ' + policy_name)
        url = f'https://{target_fsm_server}:9443/dlp/rest/v1/policy/rules'
        headers = {'Authorization': f'Bearer {target_token}', 'Content-Type': 'application/json'}
        r = requests.post(url, headers=headers, data=rules_classifiers_output, verify=False)
        logger.info("Request returned: " + str(r.status_code)) 
        return r.status_code

    def post_severity_action(logger, target_token, target_fsm_server, severity_action_output, policy_name):
        # post the input of: /dlp/rest/v1/policy/rules/severity-action?policyName=
        logger.info('Push rule severity and action to: ' + target_fsm_server + ' policy: ' + policy_name)
        url = f'https://{target_fsm_server}:9443/dlp/rest/v1/policy/rules/severity-action'
        headers = {'Authorization': f'Bearer {target_token}', 'Content-Type': 'application/json'}
        r = requests.post(url, headers=headers, data=severity_action_output, verify=False)
        logger.info("Request returned: " + str(r.status_code)) 

    def post_source_destination(logger, target_token, target_fsm_server, source_destination_output, policy_name):
        # post the input of: /dlp/rest/v1/policy/rules/source-destination
        logger.info('Push rule source and destination to:  ' + target_fsm_server + ' policy: ' + policy_name)
        url = f'https://{target_fsm_server}:9443/dlp/rest/v1/policy/rules/source-destination'
        headers = {'Authorization': f'Bearer {target_token}', 'Content-Type': 'application/json'}
        r = requests.post(url, headers=headers, data=source_destination_output, verify=False)
        logger.info("Request returned: " + str(r.status_code)) 

    def post_rule_exception(logger, target_token, target_fsm_server, rule_exception_output, rule_name):
        # post the input of: /dlp/rest/v1/policy/rules/exceptions
        logger.info('Push rule exception to: ' + target_fsm_server + ' rule name: ' + rule_name)
        url = f'https://{target_fsm_server}:9443/dlp/rest/v1/policy/rules/exceptions'
        headers = {'Authorization': f'Bearer {target_token}', 'Content-Type': 'application/json'}
        r = requests.post(url, headers=headers, data=rule_exception_output, verify=False)
        logger.info("Request returned: " + str(r.status_code)) 

# end PostPolicies