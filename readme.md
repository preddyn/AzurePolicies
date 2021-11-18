# Azure Custom Policies 

Azure policies can audit & deny default Network Security Groups

## Prerequisites 

- Verify Python >= 3.7 is installed.  Check the installed version using:
```
python -V
```
    or
```
python3 -V
```
- Create a working directory and make it the current directory.  Note: the path shown is for illustration only.
```
mkdir /path/to/working_directory
cd /path/to/working_dir
or
cd azurepolicies
```
- Import module dependencies using:
```
pip install -r ./requirements.txt
```
    or
```
pip3 install -r ./requirements.txt
```
- Login into your Microsoft Azure account and set your subscription:
```
az login 
az account set --subscription "Provide your subscription name/ID"
az account show
```
- Register the Azure Policy Insights resource provider using Azure CLI:
```
az provider register --namespace 'Microsoft.PolicyInsights' 
```

## Create Policy Definition

- Create a policy definition with built-in azure poilicies, built-in policies are provided by microsoft.
- Create Custom policies which can deny default Network Security groups & management port exposure

```
python3 AKSPolicy.py
```


### Note: Currently all AKS policies are Azure built-in policies. 


## Clean up resources 

- To remove the assignment created, first disable the assignment then use the following command to delete the policy
```
az policy assignment delete --name 'Default Policies' --scope '/subscriptions/<subscriptionID>'
```


## [Reference](https://docs.microsoft.com/en-us/cli/azure/policy/definition?view=azure-cli-latest#az-policy-definition-create)
## [AzureSDK](https://docs.microsoft.com/it-it/python/api/azure-mgmt-resource/azure.mgmt.resource?view=azure-python)