# M365-Bulk-User-Auth-Reset
Powershell script that cycles through a list of M365 user (users.txt) and performs the following actions for each user:  
- revoke all active sessions
- force password change at next logon
- enable MFA

This script might turn out to be usefull when reponding to an incident or when strengthening the security of your M365 environment.
