﻿# import-export

Forcepoint DLP has a RestAPI to import and export policy details.
you can use the export or import script to backup transfer or automate actions.

the Usage format is: 

python export_policies.py --source_fsm youroldfsm.net --source_user serviceaccount --source_pwd passwd --type DLP

python export_policies.py --source_fsm youroldfsm.net --source_user serviceaccount --source_pwd passwd --type Discovery


python import_policies.py --target_fsm yournewfsm.net --target_user serviceaccount --target_pwd passwd --type DLP

python import_policies.py --target_fsm yournewfsm.net --target_user serviceaccount --target_pwd passwd --type Discovery



When importing policies, the script assume that the policy files are located in the folder named "json" on the same location as the script. See the examples for details. 


This requires having a RestAPI user on the FSM. you can't work with a regular administrator for RestAPI activities.


on this version we don't handle custom keyphases, dictionaries, fingerprint, action plans, etc.

Contact Forcepoint support or the customer hub for more information.
