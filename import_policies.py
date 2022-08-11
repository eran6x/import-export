"""

import policies.
==============================

"""
import argparse
import time
import logging

import common

####
## Import the policies from file to the new FSM
##  
####
def main_import():
    """ 
        import policies to target_fsm, get a list of enabled policies and iterate
        on every policy to GET the policies and rules and POST them into the target fsm,
        print to screen, later on write to the logs. 
    """
    # configure the logger
    logging.basicConfig(filename="import-api.log",
                        format='%(asctime)s %(message)s',
                        filemode='w', level=logging.DEBUG)
    logger = logging.getLogger()

    # create command line arguments

    parser = argparse.ArgumentParser(description='This script imports policies to the target FSM.\nBoth DLP and Discovery policies are supported.')

    parser.add_argument('-t', '--target_fsm', nargs='?', const=1, type=str,
                        default='', help='Target FSM ip or hostname.', required=True)
    parser.add_argument('-tu', '--target_user', nargs='?', const=1, type=str,
                        default='', help='Target FSM application user name.', required=True)
    parser.add_argument('-tp', '--target_pwd', nargs='?', const=1, type=str,
                        default='', help='Target FSM application user password.', required=True)
    parser.add_argument('-e', '--type', nargs='?', const=1, type=str,
                        default='', help='Policy type, "DLP" or "Discovery" ', required=True)
    #parser.add_argument('-D', '--deploy', nargs='?', const=1, type=str,
    #                    default='', help='Policy type, "DLP" or "Discovery" ', required=False)

    # parse cli arguments
    args = parser.parse_args()
    target_fsm_server = args.target_fsm
    tgt_user_name = args.target_user
    tgt_user_pwd = args.target_pwd
    policy_type = args.type

    # set start time to calculate the run time at the end of the run
    start_time = time.time()

    # init the classes for logger
    get_jwt = common.Auth(logger)
    common.GetPoliciesFromFile(logger)
    common.PostPolicies(logger)

    # start to import  policies
    print('\nImporting ' + policy_type + ' Policies from local files')

    # get enabled policies
    enabled_policies = common.GetPoliciesFromFile.get_policy_list(logger, policy_type)

    # get rule exceptions
    rule_exceptions = common.GetPoliciesFromFile.get_all_exceptions(logger, policy_type)

    
    # start to import  policies
    total_enabled_policies = enabled_policies['total_enabled_policies']
    print('Total ' + policy_type + ' policies enabled found: ' + str(total_enabled_policies))
    total_exceptions_policies = len(rule_exceptions)
    print('Exception List include ' + str(total_exceptions_policies) +  ' entries.')
    print('--------------------------------------------------------')
    # print total enabled policies on source fsm
    print('\nStarting to import ' + policy_type + ' policies into target FSM: ' + target_fsm_server)
    # get token from target fsm
    #print('\nSending request to get JWT from target FSM')
        
    failed_to_import_policies = 0
    notsupported_policies = 0

    target_token = get_jwt.get_access_token(target_fsm_server, tgt_user_name, tgt_user_pwd)

    print('--------------------------------------------------------')
    # import polices and rules from source fsm, itterate over the list of policies and refresh token along the way
    for pn in enabled_policies['enabled_policies']:
        policy_name = pn

        # check run time
        run_time = time.time() - start_time
        if run_time > 600:
            # refresh token
            target_token = get_jwt.get_access_token(target_fsm_server, tgt_user_name, tgt_user_pwd)
            start_time = time.time()

        if policy_name == 'Email DLP Policy' or policy_name == 'Web DLP Policy':
            notsupported_policies = notsupported_policies + 1
            print(policy_name + ': Quick Policies are not supported and will not be imported')
            continue

        # Load and import DLP policies and rules from source fsm
        if policy_type == 'DLP':
            print('Loading ' + policy_type + ' policy: ' + policy_name)
            rules_classifiers_output = common.GetPoliciesFromFile.get_rules_classifiers(logger, policy_name)
            severity_action_output = common.GetPoliciesFromFile.get_severity_action(logger, policy_name)
            source_destination_output = common.GetPoliciesFromFile.get_source_destination(logger, policy_name)
            print('Importing to FSM ' + policy_type + ' policy: ' + policy_name)
            return_status = common.PostPolicies.post_rules_classifiers(logger, target_token, target_fsm_server, rules_classifiers_output, policy_name)
            if not (return_status > 201 ): # = HTTP 200 OK / 201 partial
                common.PostPolicies.post_severity_action(logger, target_token, target_fsm_server, severity_action_output, policy_name)
                common.PostPolicies.post_source_destination(logger, target_token, target_fsm_server, source_destination_output,
                                                 policy_name)
            else: # policy import failed with other HTTP code
                print('\nImport ' + policy_name + ' Failed!.HTTP request returned with status code:' + str(return_status))
                print('See log for details')
                failed_to_import_policies += 1

        else: # Discovery Policy
            print('Loading ' + policy_type + ' policy: ' + policy_name)
            rules_classifiers_output = common.GetPoliciesFromFile.get_rules_classifiers(logger, policy_name)
            severity_action_output = common.GetPoliciesFromFile.get_severity_action(logger, policy_name)

            print('Importing to FSM ' + policy_type + ' policy: ' + policy_name)
            return_status = common.PostPolicies.post_rules_classifiers(logger, target_token, target_fsm_server, rules_classifiers_output, policy_name)
            if not (return_status > 201 ): # 200 OK
                common.PostPolicies.post_severity_action(logger, target_token, target_fsm_server, severity_action_output, policy_name)
            else: 
                print('\nImport ' + policy_name + ' Failed!.HTTP request returned with status code:' + str(return_status))
                print('See log for details')
        print('--------------------------------------------------------')

    # import and export rule exceptions if they exist
    if len(rule_exceptions) == 0:
        pass
    else:
        print('\nLoading rule exceptions')
        for i in rule_exceptions['exception_rules']:
            rule_name = i['rule_name']
            rule_exception_output = common.GetPoliciesFromFile.get_rule_exception(logger, rule_name)

            print('\nImporting to FSM ' + policy_type + ' policy [' + policy_name + "] exceptions")# + str(i))
            common.PostPolicies.post_rule_exception(logger,target_token, target_fsm_server, rule_exception_output, rule_name)

    print('\nImport task completed:')
    print('Total policies enabled:      ' + str(total_enabled_policies))
    print('Total policies imported:     ' + str(total_enabled_policies - notsupported_policies - failed_to_import_policies))
    print('Total unsupported policies:  ' + str(notsupported_policies))
    print('Total failed to import:      ' + str(failed_to_import_policies))
    format_sec = "{:.2f}".format(time.time() - start_time)
    print("Total run time: " + str(format_sec) + ' seconds')
    print('--------------------------------------------------------')

#End main_import

def main():
    main_import()  # import policies to FSM


if __name__ == "__main__":
    main()
