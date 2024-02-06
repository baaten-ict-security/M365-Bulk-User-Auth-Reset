#########################################################################################################
## M365 Bulk User Auth Reset
## Version: 1.0 (20240206)
## Author: Dennis Baaten (Baaten ICT Security)
##
#### DISCRIPTION
## Powershell script that cycles through a list of M365 user (users.txt) and performs the following actions for each user:  
## - revoke all active sessions
## - force password change at next logon
## - enable MFA
## 
## This script might turn out to be usefull when reponding to an incident or when strengthening the security of your M365 environment.
## Make sure to change the filepath that points to the users.txt file. 
##
#### VERSION HISTORY
## 1.0: 
##    * original version
##
##########################################################################################################

Install-Module Microsoft.Graph
Install-Module MSOnline

Import-Module Microsoft.Graph.Authentication
Import-Module MSOnline

Connect-MgGraph -NoWelcome -Scopes Directory.AccessAsUser.All
Connect-MsolService

# set file path
# the file should list one or more User Principal Names (often the full email address); each on a new line.
$filepath = "users.txt"

# Read the user list from the text file
$users = Get-Content $filepath
Write-Host "`n------------------------`n"

# Loop through each user in the list
foreach ($account in $users) {
    Write-Host "$account"

    $user = (Get-MgUser -UserId $account -ErrorAction SilentlyContinue)
    If (!($user)) {
        Write-Host ("`t Can't find an Azure AD account for {0}" -f $account);
        Write-Host "`n------------------------`n"; 
    }
    else {
        $username = $user.UserPrincipalName
        
        # step 1: revoke all active sessions
        try {
            $status1 = Revoke-MgUserSignInSession -UserId $user.Id
            Write-Host "`t v - Refresh tokens revoked for $username"
        } 
        catch {
            Write-Host "`t x - Failed to revoke refresh token for $username"
        }

        # step 2: force password change on next logon
        try {
            $status2 = Set-MsolUserPassword -UserPrincipalName $username -ForceChangePassword:$true -ForceChangePasswordOnly:$true
            Write-Host "`t v - Password change forced for $username"
        } 
        catch {
            Write-Host "`t x - Failed to force password change for user: $username"
        }

        # step 3: enable MFA
        try {
            $status3 = Set-MsolUser -UserPrincipalName $username -StrongAuthenticationRequirements @(New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement -Property @{RelyingParty="*"; State="Enabled";})
            Write-Host "`t v - MFA enabled for user: $username"
        } 
        catch {
            Write-Host "`t x - Failed to enable MFA for user: $username"
        }
        Write-Host "`n------------------------`n"
    }
}
