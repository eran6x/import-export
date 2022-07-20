"""
Export policies
==============================

Modified version: export_policies_to_file_cli
Author: Eran Amir (July-22) 
modified version to export all policies to files.

"""
import common

import argparse
import json
import logging
import os
import time
import io
#from os import path
##import urlli3
# suppress ssl warning message
#urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main_export():
    # configure the logger
    logging.basicConfig(filename="export-api.log",
                        format='%(asctime)s %(message)s',
                        filemode='w', level=logging.DEBUG)
    logger = logging.getLogger()

    # create command line arguments

    parser = argparse.ArgumentParser(
        description='This script export policies from source FSM .\nBoth DLP and Discovery policies are supported.')

    parser.add_argument('-s', '--source_fsm', nargs='?', const=1, type=str,
                        default='', help='Source FSM ip or hostname.', required=True)
    parser.add_argument('-su', '--source_user', nargs='?', const=1, type=str,
                        default='', help='Source FSM application user name.', required=True)
    parser.add_argument('-sp', '--source_pwd', nargs='?', const=1, type=str,
                        default='', help='Source FSM application user password.', required=True)
    parser.add_argument('-e', '--type', nargs='?', const=1, type=str,
                        default='', help='Policy type, "DLP" or "Discovery" ', required=True)

    # parse cli arguments
    args = parser.parse_args()
    source_fsm_server = args.source_fsm
    src_user_name = args.source_user
    src_user_pwd = args.source_pwd
    policy_type = args.type

    # set start time to calculate the run time at the end of the run
    start_time = time.time()

    # set the class
    get_jwt = common.Auth(logger)
    get_policies = common.GetPolicies(logger)

    # start to  export and policies
    print('\nExport ' + policy_type + ' Policies')
    print('--------------------------------------------------------')
    print('Source FSM: ' + source_fsm_server)

    # get token from source and target fsm
    print('\nSending requests to get JWT from source FSM')
    print('--------------------------------------------------------')
    source_token = get_jwt.get_access_token(source_fsm_server, src_user_name, src_user_pwd)
   
    # get enabled policies
    enabled_policies = get_policies.get_policy_list(source_token, source_fsm_server, policy_type)

    # get rule exceptions
    rule_exceptions = get_policies.get_all_exceptions(source_token, source_fsm_server, policy_type)

    """ 
        Export policies from source_fsm: 
        get a list of enabled policies and iterate on every policy to GET the policies and rules,
        severity and action.
    """

    # print total enabled policies on source fsm
    total_enabled_policies = len(enabled_policies['enabled_policies'])
    print('\nStarting to export ' + policy_type + ' policies from FSM')
    print('--------------------------------------------------------')
    print('Total ' + policy_type + ' policies enabled on source FSM: ' + str(total_enabled_policies))

    # export polices and rules from source fsm, itterate over the list of policies and refresh token along the way
    for i in enabled_policies['enabled_policies']:
        notsupported_policies = 0
        policy_name = i

        # check run time
        run_time = time.time() - start_time
        if run_time > 600:
            # refresh token
            source_token = get_jwt.get_access_token(source_fsm_server, src_user_name, src_user_pwd)
            start_time = time.time()

        if policy_name == 'Email DLP Policy' or policy_name == 'Web DLP Policy':
            notsupported_policies = notsupported_policies + 1
            print('\nExporting ' + policy_type + ' policy: ' + policy_name)
            print('--------------------------------------------------------')
            print(policy_name + ' : Quick Policies are not supported and will not be exported')
            continue

        # Export policies and rules from source fsm
        if policy_type == 'DLP':
            print('\nExporting ' + policy_type + ' DLP policy: ' + policy_name)
            print('--------------------------------------------------------')
            rules_classifiers_output = get_policies.get_rules_classifiers(source_token, source_fsm_server, policy_name)
            severity_action_output = get_policies.get_severity_action(source_token, source_fsm_server, policy_name)
            source_destination_output = get_policies.get_source_destination(source_token, source_fsm_server, policy_name)
            print('\nSaving ' + policy_type + ' DLP policy: ' + policy_name)
            print('--------------------------------------------------------')
        else:
            print('\nExporting ' + policy_type + ' Discovery policy: ' + policy_name)
            print('--------------------------------------------------------')
            rules_classifiers_output = get_policies.get_rules_classifiers(source_token, source_fsm_server, policy_name)
            severity_action_output = get_policies.get_severity_action(source_token, source_fsm_server, policy_name)

            print('\nSaving ' + policy_type + ' Discovery policy: ' + policy_name)
            print('--------------------------------------------------------')

        # Save exported json files to disk 

        os.makedirs('json', exist_ok=True)

        write_to_file(policy_name, 'json/' + policy_name + '_rules_classifiers.json', rules_classifiers_output)
        write_to_file(policy_name, 'json/' + policy_name + '_sev_action.json', severity_action_output)
        write_to_file(policy_name, 'json/' + policy_name + '_source_destination.json', source_destination_output)
        write_to_file(policy_name, 'json/' +  'enabled_policies.json', enabled_policies)

#        f = open('json/' + policy_name + '_rules_classifiers.json', 'w', encoding='utf-8')
#        json.dump(rules_classifiers_output, f, ensure_ascii=False, indent=4)

#        f = open('json/' + policy_name + '_sev_action.json', 'w', encoding='utf-8')
#        json.dump(severity_action_output, f, ensure_ascii=False, indent=4)

#        f = open('json/' + policy_name + '_source_destination.json', 'w', encoding='utf-8')
#        json.dump(source_destination_output, f, ensure_ascii=False, indent=4)

#        f = open('json/' +  'enabled_policies.json', 'w', encoding='utf-8')
#        json.dump(enabled_policies, f, ensure_ascii=False, indent=4)

    # export rule exceptions if they exist
    if (len(rule_exceptions) == 0):
        pass
    else:
        print('\Exporting rule exceptions')
        print('--------------------------------------------------------')
        for i in rule_exceptions['exception_rules']:
            rule_name = i['rule_name']
            rule_exception_output = get_policies.get_rule_exception(source_token, source_fsm_server, policy_type,rule_name)
            f = open('json/' + policy_name + '_exception_rules.json', 'w', encoding='utf-8')
            json.dump(rule_exception_output, f, ensure_ascii=False, indent=4)
                                                                    
    # print execution time in seconds
    print('\nExporting policies completed')
    print('--------------------------------------------------------')
    #total_policies_exported = total_enabled_policies - notsupported_policies
    #print('Total policies exported: ' + str(total_policies_exported))
    format_sec = "{:.2f}".format(time.time() - start_time)
    print("Total run time: " + str(format_sec) + ' seconds')
#end main export

def write_to_file(policy_name, filename, data):
    os.makedirs('json', exist_ok=True)
#    f = open('json/' + policy_name + '_rules_classifiers.json', 'w', encoding='utf-8')
#    json.dump(data, f, ensure_ascii=False, indent=4)
    # Write JSON file
    with io.open(filename, 'w', encoding='utf8') as outfile:
        json.dump(data, outfile, ensure_ascii=False, indent=4)
#        str_ = json.dumps(data,
#                        indent=4, sort_keys=True,
#                        separators=(',', ': '), ensure_ascii=False)
#        outfile.write(str_)


def main():
    main_export() # export policies from FSM

if __name__ == "__main__":
    main()