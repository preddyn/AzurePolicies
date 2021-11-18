#!/usr/bin/env python3
import os 
from azure.common.credentials import get_azure_cli_credentials
from azure.mgmt.resource import *
from azure.mgmt.resource.policy.v2019_09_01.models  import *
import json

#Standard values 
metadat={"category": 'Network'}
policy_name = "default_Policies"
policy_description = "initiative is to audit resources with default NSG rules, storage acconts with no firewalls, audit unenrcypted communications. Deny default NSG rule creation with Custom policies"
parameter_name = "effect"
parameter_description = "Enforce this policy using Audit/deny mode"

#capture credentials & subscription ID details  from Cli Session 
try:
    credentials, subscription = get_azure_cli_credentials()
except: 
    print("There is no active azurecli session, please check if you have an active session")
    sys.exit(1)

#print subscription ID on which you're applying policies 
print("Authenticated Azure Cli session is set to SubscriptionID : ",subscription,"\n")

#Initialize policyclient class
try: 
    policy_client = PolicyClient(credential=credentials, subscription_id=subscription, api_version='2019-09-01')
#define parameters required for your custom policy(Management ports open from internet)
    parameter_metadata = ParameterDefinitionsValueMetadata(additional_properties=None, display_name=parameter_name, description=parameter_description)
    parameter_def_value = ParameterDefinitionsValue(type='String', allowed_values=["audit", "deny"], default_value='deny', metadata=parameter_metadata)
    parameter_def_value1 = ParameterDefinitionsValue(type='String', allowed_values=["audit", "deny"], default_value='audit', metadata=parameter_metadata)

#parse the parameter_Def_value to dict
    parametervalue = {"effect": parameter_def_value}
    parametervalue1 = {"effect": parameter_def_value1}


except:
    print("Error : Policy client module is not loaded, please check if python SDK for Azure is updated\n")

#read the policy rule json which is used for Custom policy creation 

def CreateCustomPolicy(inputCustomPolicyFile, custom_policy):
    try:
        policy_rule_context = { }
        with open(inputCustomPolicyFile) as policyfile:
            policy_rule_context = json.load(policyfile)
    #define Custom policy which deny's NSG rule creation with default network rules(inbound access from internet to ports 21,22,23,139,1443,3389)
        policy_definition = PolicyDefinition(policy_type='Custom', mode='All', display_name=custom_policy, description=policy_description, policy_rule=policy_rule_context, metadata=metadat, parameters=parametervalue)
        policy_def_output = policy_client.policy_definitions.create_or_update(custom_policy, policy_definition)
        return policy_def_output
    except:
        print("Error : Check file location & permissions on custom_policies dir or provided .json files  \n")
        sys.exit(1)

deny_policy_def_output = CreateCustomPolicy("./custom_policies/NSG_Deny_managementports.json", "Deny_default_NSG_rules")
ingress_policy_def_output = CreateCustomPolicy("./custom_policies/NSG_egress.json", "Audit_Non_IPs")

#group built in policies and custom policies as an initiative definition 
try:
    policy_def_reference = [PolicyDefinitionReference(policy_definition_id="/providers/Microsoft.Authorization/policyDefinitions/e372f825-a257-4fb8-9175-797a8a8627d6", parameters=None, policy_definition_reference_id=None, group_names=None)]
    policy_def_reference.append(PolicyDefinitionReference(policy_definition_id="/providers/Microsoft.Authorization/policyDefinitions/2c89a2e5-7285-40fe-afe0-ae8654b92fab", parameters=None, policy_definition_reference_id=None, group_names=None))
    policy_def_reference.append(PolicyDefinitionReference(policy_definition_id="/providers/Microsoft.Authorization/policyDefinitions/e71308d3-144b-4262-b144-efdc3cc90517", parameters=None, policy_definition_reference_id=None, group_names=None))
    policy_def_reference.append(PolicyDefinitionReference(policy_definition_id="/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9", parameters=None, policy_definition_reference_id=None, group_names=None))
    policy_def_reference.append(PolicyDefinitionReference(policy_definition_id="/providers/Microsoft.Authorization/policyDefinitions/34c877ad-507e-4c82-993e-3452a6e0ad3c", parameters=None, policy_definition_reference_id=None, group_names=None))
    policy_def_reference.append(PolicyDefinitionReference(policy_definition_id="/providers/Microsoft.Authorization/policyDefinitions/2c89a2e5-7285-40fe-afe0-ae8654b92fb2", parameters=None, policy_definition_reference_id=None, group_names=None))
    policy_def_reference.append(PolicyDefinitionReference(policy_definition_id="/providers/Microsoft.Authorization/policyDefinitions/06a78e20-9358-41c9-923c-fb736d382a4d", parameters=None, policy_definition_reference_id=None, group_names=None))
    policy_def_reference.append(PolicyDefinitionReference(policy_definition_id="/providers/Microsoft.Authorization/policyDefinitions/0961003e-5a0a-4549-abde-af6a37f2724d", parameters=None, policy_definition_reference_id=None, group_names=None))
    policy_def_reference.append(PolicyDefinitionReference(policy_definition_id=deny_policy_def_output.id, parameters=None, policy_definition_reference_id=None, group_names=None))
    policy_def_reference.append(PolicyDefinitionReference(policy_definition_id=ingress_policy_def_output.id, parameters=None, policy_definition_reference_id=None, group_names=None))

#Set initiative definition from above grouped sub policies 
    policy_set_def = PolicySetDefinition(policy_type='Custom', display_name=policy_name, description=policy_description, metadata=metadat, parameters=parameters, policy_definitions=policy_def_reference, policy_definition_groups=None)
    policy_set_defoutput = policy_client.policy_set_definitions.create_or_update(policy_name, policy_set_def)
    print("Details of Intiative defintion created making use of built-in & custom polices : ",policy_set_defoutput,"\n")
except:
    print("Error : Check permissions of authenticated session user, to verify if user is authorized to create Custom policy \n")
    sys.exit(1)

#Create a policy assignment to apply the intiative definition above
try:
    policy_assignment = PolicyAssignment(display_name=policy_name, policy_definition_id=policy_set_defoutput.id, scope='/subscriptions/'+subscription, not_scopes=None, parameters=None, description=policy_description, metadata=metadat, enforcement_mode='Default', sku=None, location=None, identity=None)
    policy_assignment_output = policy_client.policy_assignments.create(scope='/subscriptions/'+subscription, policy_assignment_name=policy_name, parameters=policy_assignment, custom_headers=None, raw=False)
    policy_assignment_result = policy_client.policy_assignments.get_by_id(policy_assignment_output.id, custom_headers=None, raw=False)
except:
    print("Error : Check permissions of authenticated session user, to verify if user is authorized to assign policies\n")

#Print Assigned policy details 
print("Details of policy assignment, i.e, name, scope",policy_assignment_result)



