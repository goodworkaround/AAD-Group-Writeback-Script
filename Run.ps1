# Read configuration
$ErrorActionPreference = "Stop"
$Config = Get-Content .\Run.config | ConvertFrom-Json

# Set preferences
if($Config.VerbosePreference -in "Continue","SilentlyContinue") {
    $VerbosePreference = $Config.VerbosePreference
} else {
    $VerbosePreference = "Continue"
    Write-Verbose "Enabling verbose output by default. Disable by adding VerbosePreference = Continue in Run.config"
}

if($Config.DebugPreference -in "Continue","SilentlyContinue") {
    $DebugPreference = $Config.DebugPreference
} else {
    $DebugPreference = "SilentlyContinue"
}

# Import modules
Import-Module .\AuthenticationMethods\MSI.psm1 -Force -Verbose:$false
Import-Module .\AuthenticationMethods\ClientCredentials.psm1 -Force -Verbose:$false
Import-Module .\HelperFunctions.psm1 -DisableNameChecking -Force -Verbose:$false

# Get access token
$AccessToken = $null
if($Config.AuthenticationMethod -eq "MSI") {
    $AccessToken = Get-MSIMSGraphAccessToken
} elseif($Config.AuthenticationMethod -eq "ClientCredentials") {
    $AccessToken = Get-ClientCredentialsMSGraphAccessToken -ClientID $Config.ClientID -EncryptedSecret $Config.EncryptedSecret -TenantID $Config.TenantID
} else {
    Write-Error "Unknown value for AuthenticationMethod: $($Config.AuthenticationMethod)" -ErrorAction Stop
}

# Verify access token
$JWT = ConvertFrom-Base64JWT $AccessToken
if($JWT.Payload.roles -notcontains "Group.Read.All") {
    Write-Warning "Could not find Group.Read.All in access token roles. Things might not work as intended. Make sure you have the correct scopes added."
} elseif($jwt.Payload.aud) {
    Write-Verbose "Successfully received access token"
} else {
    Write-Error "Someting went wrong when getting access token"
}

# Get all scoped groups
Write-Verbose "Getting all scoped groups"
$ScopedGroups = $null
if($Config.AADGroupScopingMethod -eq "PrivilegedGroups") {
    $ScopedGroups = Get-GraphRequestRecursive -Url 'https://graph.microsoft.com/v1.0/groups?$filter=isAssignableToRole eq true' -AccessToken $AccessToken
} elseif($Config.AADGroupScopingMethod -eq "Filter") {
    $ScopedGroups = Get-GraphRequestRecursive -Url ('https://graph.microsoft.com/v1.0/groups?$filter={0}' -f $Config.AADGroupScopingFilter) -AccessToken $AccessToken
} else {
    Write-Error "Unknown value for AADGroupScopingMethod: $($Config.AADGroupScopingMethod)" -ErrorAction Stop
}
Write-Verbose "Found $(($ScopedGroups|Measure-Object).Count) groups in scope"

# Get or create AD groups for all scoped groups. The returned object will be a dictionary with the ADGroupObjectIDAttribute as key
$ADGroupsMap = $ScopedGroups | Ensure-ADGroup -ADGroupObjectIDAttribute $Config.ADGroupObjectIDAttribute -DestinationOU $Config.DestinationOU -ErrorAction Stop

# Parse through all scoped groups, maintaining AD group memberships
Write-Verbose "Processing all memberships"
Foreach($ScopedGroup in $ScopedGroups) {
    Write-Verbose "Processing group '$($ScopedGroup.displayName)' ($($ScopedGroup.id))"
    $Members = Get-GraphRequestRecursive -Url "https://graph.microsoft.com/v1.0/groups/$($ScopedGroup.id)/members?`$select=id,displayName,userPrincipalName,onPremisesDistinguishedName,onPremisesImmutableId" -AccessToken $AccessToken
    
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
    if($ADGroupsMap.Contains($ScopedGroup.Id)) {
        $ADGroup = $ADGroupsMap[$ScopedGroup.Id]
        
        # Find members in AD, that should not be there, and remove them
        $ADGroup.members | 
            Where-Object {$_ -notin $ExpectedADMembers} |
            ForEach-Object {
                Write-Verbose "Removing member from AD group '$($ADGroup.displayName)': $($_)"
                Remove-ADGroupMember -Identity $ADGroup.DistinguishedName -Members $_ -Confirm:$false
            }
        
        # Find members from Azure AD, that is not in AD, and add them
        $ExpectedADMembers |
            Where-Object {$_ -notin $ADGroup.Members} |
            ForEach-Object {
                Write-Verbose "Adding member to AD group '$($ADGroup.displayName)': $($_)"
                Add-ADGroupMember -Identity $ADGroup.DistinguishedName -Members $_
            }
    } else {
        Write-Warning "Unable to find AD group for AAD group '$($ScopedGroup.displayName)' ($($ScopedGroup.id))"
    }
}
