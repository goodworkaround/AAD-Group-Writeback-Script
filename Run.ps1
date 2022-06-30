[CmdletBinding(SupportsShouldProcess)]
Param
(
    [Parameter(Mandatory=$false,
                ValueFromPipeline=$true,
                Position=0)]
    [ValidateScript( {Test-Path -Path $_ -IsValid})]
    [ValidateNotNullOrEmpty()]
    $ConfigFile = ".\Run.config"
)

# Read configuration
$ErrorActionPreference = "Stop"
$Config = Get-Content -path $ConfigFile | ConvertFrom-Json
# Check configuration
Test-Configuration $Config -ErrorAction Stop

# Import modules
Import-Module .\HelperFunctions.psm1 -DisableNameChecking -Force -Verbose:$VerbosePreference
Import-Module .\AuthenticationMethods\MSI.psm1 -Force -Verbose:$VerbosePreference
Import-Module .\AuthenticationMethods\ClientCredentials.psm1 -Force -Verbose:$VerbosePreference

Import-Module ActiveDirectory -Verbose:$VerbosePreference

$graphEnvironment = $config.Environment
if ($graphEnvironment -eq $null)
{
    $graphEnvironment = "AzureCloud"
}

$graphEndpoints = Initialize-GraphEnvironment -Environment $graphEnvironment

# Get access token
$AccessToken = $null
if($Config.AuthenticationMethod -eq "MSI") {
    $AccessToken = Get-MSIMSGraphAccessToken -GraphUrl $graphEndpoints.GraphUrl -Verbose:$VerbosePreference
} elseif($Config.AuthenticationMethod -eq "ClientCredentials") {
    $AccessToken = Get-ClientCredentialsMSGraphAccessToken -ClientID $Config.ClientID -EncryptedSecret $Config.EncryptedSecret -TenantID $Config.TenantID -LoginUrl $graphEndpoints.LoginUrl -GraphUrl $graphEndpoints.GraphUrl -Verbose:$VerbosePreference
} else {
    Write-Error "Unknown value for AuthenticationMethod: $($Config.AuthenticationMethod)" -ErrorAction Stop
}

# Verify access token
$JWT = ConvertFrom-Base64JWT $AccessToken
if($JWT.Payload.roles -notcontains "Group.Read.All") {
    if($Config.AuthenticationMethod -eq "MSI") {
        Write-Warning "Could not find Group.Read.All in access token roles. Things might not work as intended. Make sure you have the correct scopes added. Make sure you follow https://github.com/goodworkaround/AAD-Group-Writeback-Script#managed-service-identity-msi in order to configure MSI. If you recently added permissions using New-AzureADServiceAppRoleAssignment, and you ran into this error BEFORE running New-AzureADServiceAppRoleAssignment, please wait an hour until a new access token is available through MSI."
    } else {
        Write-Warning "Could not find Group.Read.All in access token roles. Things might not work as intended. Make sure you have the correct scopes added. "
    }
} 

if($JWT.Payload.roles -notcontains "User.Read.All") {
    if($Config.AuthenticationMethod -eq "MSI") {
        Write-Warning "Could not find User.Read.All in access token roles. Things might not work as intended. Make sure you have the correct scopes added. Make sure you follow https://github.com/goodworkaround/AAD-Group-Writeback-Script#managed-service-identity-msi in order to configure MSI. If you recently added permissions using New-AzureADServiceAppRoleAssignment, and you ran into this error BEFORE running New-AzureADServiceAppRoleAssignment, please wait an hour until a new access token is available through MSI."
    } else {
        Write-Warning "Could not find User.Read.All in access token roles. Things might not work as intended. Make sure you have the correct scopes added. "
    }
} 

if($jwt.Payload.aud) {
    Write-Verbose "Successfully received access token"
    Write-Verbose " - oid:             $($jwt.payload.oid)"
    Write-Verbose " - aud:             $($jwt.payload.oid)"
    Write-Verbose " - iss:             $($jwt.payload.iss)"
    Write-Verbose " - appid:           $($jwt.payload.appid)"
    Write-Verbose " - app_displayname: $($jwt.payload.app_displayname)"
    Write-Verbose " - roles:           $($jwt.payload.roles)"
} else {
    Write-Error "Someting went wrong when getting access token" -ErrorAction Stop
}

# Get all scoped groups
Write-Verbose "Getting all scoped groups"
$ScopedGroups = $null
if($Config.AADGroupScopingMethod -eq "PrivilegedGroups") {
    $ScopedGroups = Get-GraphRequestRecursive -Url "$($graphEndpoints.GraphUrl)/v1.0/groups?`$filter=isAssignableToRole eq true" -AccessToken $AccessToken -ErrorAction Stop
} elseif($Config.AADGroupScopingMethod -eq "Filter") {
    if(!$Config.AADGroupScopingConfig) {
        Write-Error "AADGroupScopingMethod 'Filter' requires the AADGroupScopingConfig to be set to a filter"
    }
    $ScopedGroups = Get-GraphRequestRecursive -Url ("$($graphEndpoints.GraphUrl)/v1.0/groups?`$filter={0}" -f $Config.AADGroupScopingConfig) -AccessToken $AccessToken -ErrorAction Stop
} elseif($Config.AADGroupScopingMethod -eq "GroupMemberOfGroup") {
    $ScopedGroups = Get-GraphRequestRecursive -Url ("$($graphEndpoints.GraphUrl)/v1.0/groups/{0}/members" -f $Config.AADGroupScopingConfig) -AccessToken $AccessToken -ErrorAction Stop
} else {
    Write-Error "Unknown value for AADGroupScopingMethod: $($Config.AADGroupScopingMethod)" -ErrorAction Stop
}
Write-Verbose "Found $(($ScopedGroups|Measure-Object).Count) groups in scope"

# Get or create AD groups for all scoped groups. The returned object will be a dictionary with the ADGroupObjectIDAttribute as key
$ADGroupsMap = $ScopedGroups | Save-ADGroup -ADGroupObjectIDAttribute $Config.ADGroupObjectIDAttribute -DestinationOU $Config.DestinationOU -ErrorAction Stop -Verbose:($VerbosePreference -eq 'Continue') -WhatIf:$WhatIfPreference -ADGroupNamePattern $Config.ADGroupNamePattern

# Parse through all scoped groups, maintaining AD group memberships
$ErrorActionPreference = "Continue" # No need to fail hard anymore. This reduces the risk of the script failing on ONE user causing issues.
Write-Verbose "Processing all memberships"
Foreach($ScopedGroup in $ScopedGroups) {
    Write-Verbose " - Processing group '$($ScopedGroup.displayName)' ($($ScopedGroup.id))"
    if ($Config.TransitiveMembers -eq 'true') {
        $Members = Get-GraphRequestRecursive -Url "$($graphEndpoints.GraphUrl)/v1.0/groups/$($ScopedGroup.id)/transitiveMembers/microsoft.graph.user?`$count=true&`$select=id,userType,displayName,userPrincipalName,onPremisesDistinguishedName,onPremisesImmutableId" -AccessToken $AccessToken -AdditionalHeaders @{ConsistencyLevel = 'eventual' }
    } else {
        $Members = Get-GraphRequestRecursive -Url "$($graphEndpoints.GraphUrl)/v1.0/groups/$($ScopedGroup.id)/members?`$select=id,userType,displayName,userPrincipalName,onPremisesDistinguishedName,onPremisesImmutableId" -AccessToken $AccessToken
    }

    # Get all onPremisesDistinguishedName values from AAD, which should be our correct list
    $ExpectedADMembers = $Members | 
        Where-Object onPremisesDistinguishedName | 
        Select-Object -ExpandProperty onPremisesDistinguishedName

    # Print warnings for members that are enot synced from AD
    $Members | 
        Where-Object {!$_.onPremisesDistinguishedName} | 
        ForEach-Object {
            Write-Warning "Group member '$($_.displayName)' ($($_.id)) in group '$($ScopedGroup.displayName)' ($($ScopedGroup.id)) is not synced from AD and will be ignored"
        }

    # If an AD group exists for the AAD group (should always happen)
    if($ADGroupsMap.Contains($ScopedGroup.Id) -and $ADGroupsMap[$ScopedGroup.Id].DistinguishedName) {
        $ADGroup = $ADGroupsMap[$ScopedGroup.Id]
        
        # Find members in AD, that should not be there, and remove them
        if($ADGroup.members) {
            $ADGroup.members | 
                Where-Object {$_ -notin $ExpectedADMembers} |
                ForEach-Object {
                    Write-Verbose "  - Removing member from AD group '$($ADGroup.displayName)': $($_)"
                    Remove-ADGroupMember -Identity $ADGroup.DistinguishedName -Members $_ -Confirm:$false -WhatIf:$WhatIfPreference
                }
        }
        
        # Find members from Azure AD, that is not in AD, and add them
        $ExpectedADMembers |
            Where-Object {$_ -notin $ADGroup.Members} |
            ForEach-Object {
                Write-Verbose "  - Adding member to AD group '$($ADGroup.displayName)': $($_)"
                Add-ADGroupMember -Identity $ADGroup.DistinguishedName -Members $_ -WhatIf:$WhatIfPreference
            }
    } else {
        Write-Warning "Unable to find AD group for AAD group '$($ScopedGroup.displayName)' ($($ScopedGroup.id))"
    }
}

# Determine if any AD groups should be deleted
Write-Verbose "Determining whether there are AD groups to deprovision"
$ADGroupsForDeletion = Get-ADGroupForDeprovisioning -ScopedGroups $ScopedGroups -DestinationOU $Config.DestinationOU -ADGroupObjectIDAttribute $Config.ADGroupObjectIDAttribute -GroupDeprovisioningMethod $Config.GroupDeprovisioningMethod
$Measure = $ADGroupsForDeletion | Measure-Object
if($Measure.count -gt 0) {
    if($Config.GroupDeprovisioningMethod -eq "Delete") {
        Write-Verbose "Starting deletion of groups"
        $ADGroupsForDeletion | ForEach-Object {
            Write-Verbose " - Deleting AD group: $($_.DistinguishedName)"
            $_ | Remove-ADGroup -Confirm:$false -WhatIf:$WhatIfPreference
        }
    } elseif($Config.GroupDeprovisioningMethod -eq "PrintWarning") {
        Write-Verbose "Print group deletions as warnings"
        $ADGroupsForDeletion | ForEach-Object {
            Write-Warning "Pending AD group deletion: $($_.DistinguishedName)"
        }
    } elseif($Config.GroupDeprovisioningMethod -eq "ConvertToDistributionGroup") {
        Write-Verbose "Converting AD groups that should be deleted, to distribution groups"
        $ADGroupsForDeletion | ForEach-Object {
            Write-Verbose " - Converting AD group: $($_.DistinguishedName)"
            $_ | Set-ADGroup -GroupCategory Distribution -WhatIf:$WhatIfPreference
        }
    } else {
        Write-Verbose "There are $($ADGroupsForDeletion.count) groups that should be delete. Set GroupDeprovisioningMethod to 'Delete', 'PrintWarning' or 'ConvertToDistributionGroup' in order to enable deprovisioning."
    }
} else {
    Write-Verbose  "No groups that should be deprovisioned"
}
