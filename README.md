# AAD Group Writeback Script

This repository contains a script that can take certain groups in an Azure Active Directory, defined by a scope, writing them back to onpremises Active Directory, including group memberships.

## Invocation

The script is invoked using Run.ps1, with the ConfigFile parameter. If Run.ps1 is run without parameter, "Run.config" is the default value.

## Configuration

The configuration file is a JSON based, and contains a dictionary with key-value pairs. There are three example configuration files provided:

| File | Description |
| - | - |
| Example1.config | Using client credentials to authenticate to Azure AD, writing all privileged groups back to AD. If groups are deleted from Azure AD, a list of warnings are printed. |
| Example2.config | Using Managed Service Identity to authenticate to Azure AD, writing a filtered list of groups back to AD. If groups are deleted from Azure AD, the AD group will be converted to a distribution group (which does not give any access, and is an effective disable method). |
| Example3.config | Using Managed Service Identity to authenticate to Azure AD, writing all groups that are member of the group '5f7ab793-e722-435a-a8bf-ac48a3f7361e' back to AD. If groups are deleted from Azure AD, the AD group will be deleted. |

