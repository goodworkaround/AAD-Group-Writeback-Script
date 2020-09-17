function Get-GraphRequestRecursive {
    [CmdletBinding()]
    [Alias()]
    Param
    (
        # Graph access token
        [Parameter(Mandatory = $true,
            Position = 0)]
        [String] $AccessToken,

        # Graph url
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 1)]
        [String] $Url
    )
 
    Write-Debug "Fetching url $Url"
    $Result = Invoke-RestMethod $Url -Headers @{Authorization = "Bearer $AccessToken" } -Verbose:$false
    if ($Result.value) {
        $Result.value
    }

    # Calls itself when there is a nextlink, in order to get next page
    if ($Result.'@odata.nextLink') {
        Get-GraphRequestRecursive -Url $Result.'@odata.nextLink' -AccessToken $AccessToken
    }
}



<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Save-ADGroup {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    Param
    (
        # AD attribute used for anchoring, will contain the objectid from Azure AD
        [Parameter(Mandatory = $true,
            Position = 0)]
        [string] $ADGroupObjectIDAttribute,

        # The OU where all groups will be created and is expected to reside
        [Parameter(Mandatory = $true,
            Position = 1)]
        [string] $DestinationOU,

        # The pipeline input object, an Azure AD group
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 2)]
        $AADGroup
    )

    Begin {
        Write-Verbose "Starting Save-ADGroup"

        Write-Debug "Getting all groups from destination OU, as this is faster than querying each group one at a time"
        $ADGroupMap = @{}

        Get-ADGroup -SearchBase $DestinationOU -Filter * -Properties members,$ADGroupObjectIDAttribute,displayName,name |
            Where-Object {$_.$ADGroupObjectIDAttribute} |
            ForEach-Object {
                $ADGroupMap[$_.$ADGroupObjectIDAttribute] = $_
            }
    }
    Process {
        Write-Verbose " - Processing AADGroup '$($AADGroup.displayName)' ($($AADGroup.id))"
        if(!$ADGroupMap.Contains($AADGroup.id)) {
            Write-Verbose "  - Creating group '$($AADGroup.displayName)' in AD"
            $ADGroupMap[$AADGroup.id] = New-ADGroup -Name $AADGroup.displayName -DisplayName $AADGroup.displayName -GroupScope Global -GroupCategory Security -Path $DestinationOU -OtherAttributes @{"$($ADGroupObjectIDAttribute)" = $AADGroup.id} | Get-ADGroup -Properties members,$ADGroupObjectIDAttribute,displayName,name
        } else {
            $ADGroup = $ADGroupMap[$AADGroup.id]
            if($AADGroup.displayName -ne $ADGroup.displayName) {
                Write-Verbose "  - Fixing displayname of AD group: '$($ADGroup.DisplayName)' -> $($AADGroup.displayName)"
                $ADGroup | Set-ADGroup -DisplayName $AADGroup.displayName
            }

            if($AADGroup.displayName -ne $ADGroup.name) {
                Write-Verbose "  - Fixing name of AD group: '$($ADGroup.name)' -> $($AADGroup.displayName)"
                $ADGroup | Set-ADGroup -Name $AADGroup.displayName
            }

            if($ADGroup.GroupCategory -ne 'Security' -or $ADGroup.GroupScope -ne 'Global') {
                Write-Verbose "  - Changing group scope and category to global security"
                $ADGroup | Set-ADGroup -GroupScope Global -GroupCategory Security
            }
        }
    }
    End {
        Write-Verbose "Save-ADGroup finished"
        return $ADGroupMap
    }
}


# Helper to make sure length is always divisible by 4
function ConvertFrom-Base64JWTLengthHelper 
{
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        $String
    )

    Process {
        $Length = $String.Length
        if($String.Length % 4 -ne 0) {
            $Length += 4 - ($String.Length % 4)
        }
        return $String.PadRight($Length, "=")
    }
}


<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function ConvertFrom-Base64JWT
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        $Base64JWT
    )

    Begin
    {
    }
    Process
    {
        $Spl = $Base64JWT.Split(".")
        [PSCustomObject] @{
            Header = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((ConvertFrom-Base64JWTLengthHelper $Spl[0]))) | ConvertFrom-Json
            Payload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((ConvertFrom-Base64JWTLengthHelper $Spl[1]))) | ConvertFrom-Json
        }
    }
    End
    {
    }
}



<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Test-Configuration
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        $Config
    )

    Begin
    {
    }
    Process
    {
        # Error if destination ou is not set
        if(!$Config.DestinationOU) {
            Write-Error "Mssing DestinationOU configuration setting"
        }

        # Error if destination ou does not exist
        try {
            Get-ADOrganizationalUnit $Config.DestinationOU | Out-Null
        } catch {
            Write-Error "Cannot find OU '$($Config.DestinationOU)'" -Exception $_
        }

        # Check required attributes for authentication method ClientCredentials
        if($Config.AuthenticationMethod -eq "ClientCredentials") {
            if($Config.ClientID -notmatch "[a-f0-9A-F]{8}-[a-f0-9A-F]{4}-[a-f0-9A-F]{4}-[a-f0-9A-F]{4}-[a-f0-9A-F]{8}") {
                Write-Error "AuthenticationMethod 'ClientCredentials' requires ClientID setting in config to be a guid"
            }

            if(!$Config.EncryptedSecret) {
                Write-Error "AuthenticationMethod 'ClientCredentials' requires EncryptedSecret setting in config"
            }

            if($Config.TenantID -notmatch "[a-f0-9A-F]{8}-[a-f0-9A-F]{4}-[a-f0-9A-F]{4}-[a-f0-9A-F]{4}-[a-f0-9A-F]{8}") {
                Write-Error "AuthenticationMethod 'ClientCredentials' requires TenantID setting in config to be a guid"
            }
        }

        # Check required attributes for authentication method MSI
        if($Config.AuthenticationMethod -eq "MSI") {
            if($Config.ClientID) {
                Write-Warning "AuthenticationMethod 'MSI' does not need ClientID setting in config"
            }

            if(!$Config.EncryptedSecret) {
                Write-Warning "AuthenticationMethod 'MSI' does not need EncryptedSecret setting in config"
            }

            if(!$Config.TenantID) {
                Write-Warning "AuthenticationMethod 'MSI' does not need TenantID setting in config"
            }
        }

        # Check that ADGroupObjectIDAttribute is present
        if(!$Config.ADGroupObjectIDAttribute) {
            Write-Error "Missing config setting ADGroupObjectIDAttribute, suggested value is 'info'"
        }

        # Check that AADGroupScopingMethod is present
        if(!$Config.AADGroupScopingMethod){
            Write-Error "Missing config setting AADGroupScopingMethod"
        }

        # Check that AADGroupScopingMethod GroupMemberOfGroup has a valid value for AADGroupScopingConfig
        if($Config.AADGroupScopingMethod -eq 'GroupMemberOfGroup'){
            if(!$Config.AADGroupScopingConfig) {
                Write-Error "Config setting AADGroupScopingMethod 'GroupMemberOfGroup' requires the config setting 'AADGroupScopingConfig' to be present"
            }

            if($Config.AADGroupScopingConfig -notmatch "[a-f0-9A-F]{8}-[a-f0-9A-F]{4}-[a-f0-9A-F]{4}-[a-f0-9A-F]{4}-[a-f0-9A-F]{8}") {
                Write-Error "Config setting AADGroupScopingMethod 'GroupMemberOfGroup' requires the config setting 'AADGroupScopingConfig' to be a guid"
            }
        }

        # Check that AADGroupScopingMethod Filter has a value for AADGroupScopingConfig
        if($Config.AADGroupScopingMethod -eq 'Filter'){
            if(!$Config.AADGroupScopingConfig) {
                Write-Error "Config setting AADGroupScopingMethod 'Filter' requires the config setting 'AADGroupScopingConfig' to be present"
            }
        }

        if($Config.GroupDeprovisioningMethod -notin "PrintWarning","ConvertToDistributionGroup","DoNothing", "Delete") {
            Write-Error "Config setting GroupDeprovisioningMethod does not contain a valid value. Valid values are: PrintWarning, ConvertToDistributionGroup, DoNothing, Delete"
        }
    }
    End
    {
    }
}



<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-ADGroupForDeletion {
    [CmdletBinding()]
    Param
    (
        # AD groups map used to determine AD groups that SHOULD be in AD
        [Parameter(Mandatory = $true,
            Position = 0)]
        $ScopedGroups,

        [Parameter(Mandatory = $true,
            Position = 1)]
        [string] $DestinationOU,

        [Parameter(Mandatory = $true,
            Position = 2)]
        [string] $ADGroupObjectIDAttribute,

        [Parameter(Mandatory = $true,
            Position = 3)]
        [string] $GroupDeprovisioningMethod
    )

    Begin {
        
    }
    Process {
        Write-Verbose "Starting Get-ADGroupForDeletion"

        $_AADGroupsMap = @{}
        if($ScopedGroups) {
            $ScopedGroups | ForEach-Object {
                $_AADGroupsMap[$_.id] = $_
            }
        }

        Write-Debug "Getting all groups from destination OU, as this is faster than querying each group one at a time"

        Get-ADGroup -SearchBase $DestinationOU -Filter * -Properties $ADGroupObjectIDAttribute,displayName,name |
            ForEach-Object {
                if(!$_.$ADGroupObjectIDAttribute) {
                    Write-Verbose " - adding group '$($_.DistinguishedName)' to delete list because attribute $ADGroupObjectIDAttribute is not set for the group"
                    $_
                } elseif($GroupDeprovisioningMethod -eq "ConvertToDistributionGroup" -and $_.GroupCategory -eq "Distribution") {
                    Write-Debug "Ignoring group '$($_.DistinguishedName)' because it is a distribution list, and GroupDeprovisioningMethod is 'ConvertToDistributionGroup'"
                } elseif (!$_AADGroupsMap.ContainsKey($_.$ADGroupObjectIDAttribute)){
                    Write-Verbose " - adding group '$($_.DistinguishedName)' to delete list because it does not exist in Azure AD"
                    $_
                }
            }

        Write-Verbose "Ending Get-ADGroupForDeletion"
    }
    End {
    }
}


Export-ModuleMember "Get-GraphRequestRecursive", "Save-ADGroup", "ConvertFrom-Base64JWT", "Test-Configuration", "Get-ADGroupForDeletion"