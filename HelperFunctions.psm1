<#
.Synopsis
   Helper function that gets stuff from Microsoft Graph and requests all pages recursively
.DESCRIPTION
   Helper function that gets stuff from Microsoft Graph and requests all pages recursively
.EXAMPLE
   Get-GraphRequestRecursive -Url 'https://graph.microsoft.com/v1.0/groups?$filter=isAssignableToRole eq true' -AccessToken $AccessToken
.EXAMPLE
   Get-GraphRequestRecursive -Url "https://graph.microsoft.com/v1.0/groups/<guid>/members?`$select=id,displayName,userPrincipalName,onPremisesDistinguishedName,onPremisesImmutableId" -AccessToken $AccessToken
#>
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
   The function takes an array of Entra ID groups as input and ensures that they are created in AD
.DESCRIPTION
   The function takes an array of Entra ID groups as input and ensures that they are created in AD
.EXAMPLE
   $ScopedGroups | Save-ADGroup -ADGroupObjectIDAttribute $Config.ADGroupObjectIDAttribute -DestinationOU $Config.DestinationOU
#>
function Save-ADGroup {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Collections.Hashtable])]
    Param
    (
        # AD attribute used for anchoring, will contain the objectid from Entra ID
        [Parameter(Mandatory = $true,
            Position = 0)]
        [string] $ADGroupObjectIDAttribute,

        # The OU where all groups will be created and is expected to reside
        [Parameter(Mandatory = $true,
            Position = 1)]
        [string] $DestinationOU,

        # The OU where all groups will be created and is expected to reside
        [Parameter(Mandatory = $false,
            Position = 2)]
        [string] $ADGroupNamePattern = "{0} ({1})",

        # The pipeline input object, an Entra ID group
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 3)]
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

        if(!$ADGroupNamePattern) {
            $ADGroupNamePattern = "{0} ({1})"
        }
    }
    Process {
        Write-Verbose " - Processing AADGroup '$($AADGroup.displayName)' ($($AADGroup.id))"
        $ADGroupName = $ADGroupNamePattern -f $AADGroup.displayName, $AADGroup.id, $AADGroup.mailNickname
        if($ADGroupName.Length -gt 64) {
            Write-Warning "AD group name '$ADGroupName' is longer than 64 characters and will be truncated"
            $ADGroupName = $ADGroupName.Substring(0,64).Trim()
        }

        if(!$ADGroupMap.Contains($AADGroup.id)) {
            Write-Verbose "  - Creating group '$($AADGroup.displayName)' in AD"
            $NewGroup =  New-ADGroup -Name $ADGroupName -DisplayName $ADGroupName -GroupScope Global -GroupCategory Security -Path $DestinationOU -OtherAttributes @{"$($ADGroupObjectIDAttribute)" = $AADGroup.id } -PassThru
            $ADGroupMap[$AADGroup.id] = Get-ADGroup -Identity $NewGroup.SID -Properties members, $ADGroupObjectIDAttribute, displayName, name
        }
        else {
            $ADGroup = $ADGroupMap[$AADGroup.id]
            if($ADGroupName -ne $ADGroup.displayName) {
                Write-Verbose "  - Fixing displayname of AD group: '$($ADGroup.DisplayName)' -> $($ADGroupName)"
                Set-ADGroup -DisplayName $ADGroupName -Identity $ADGroup.SID
            }

            if($ADGroupName -ne $ADGroup.name) {
                Write-Verbose "  - Fixing name of AD group: '$($ADGroup.name)' -> $($ADGroupName)"
                Rename-ADObject -NewName $ADGroupName -Identity $ADGroup.SID
            }

            if ($ADGroup.GroupCategory -ne 'Security' -or $ADGroup.GroupScope -ne 'Global') {
                Write-Verbose "  - Changing group scope and category to global security"
                Set-ADGroup -GroupScope Global -GroupCategory Security -Identity $ADGroup.SID
            }
        }
    }
    End {
        Write-Verbose "Save-ADGroup finished"
        return $ADGroupMap
    }
}


<#
.Synopsis
   Helper to make sure length is always divisible by 4
.DESCRIPTION
   Helper to make sure length is always divisible by 4
.EXAMPLE
   ConvertFrom-Base64JWTLengthHelper  "abc"
#>

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
   Function that converts a JWT from its base64 version to an object
.DESCRIPTION
   Function that converts a JWT from its base64 version to an object
.EXAMPLE
   ConvertFrom-Base64JWT "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
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
   Function that valides the configuration
.DESCRIPTION
   Function that valides the configuration
.EXAMPLE
   Test-Configuration $Config
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
            Write-Error "Cannot find OU '$($Config.DestinationOU)'"
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

            if($Config.EncryptedSecret) {
                Write-Warning "AuthenticationMethod 'MSI' does not need EncryptedSecret setting in config"
            }

            if($Config.TenantID) {
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
   Function that determines all AD groups that should be deprovisionined
.DESCRIPTION
   Function that determines all AD groups that should be deprovisionined
.EXAMPLE
   Get-ADGroupForDeprovisioning -ScopedGroups $ScopedGroups -DestinationOU $Config.DestinationOU -ADGroupObjectIDAttribute $Config.ADGroupObjectIDAttribute -GroupDeprovisioningMethod $Config.GroupDeprovisioningMethod
#>
function Get-ADGroupForDeprovisioning {
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
                    Write-Verbose " - adding group '$($_.DistinguishedName)' to delete list because it does not exist in Entra ID"
                    $_
                }
            }

        Write-Verbose "Ending Get-ADGroupForDeletion"
    }
    End {
    }
}

<#
.Synopsis
   Function that specifies endpoints for Azure Services based on cloud
.DESCRIPTION
   Function that specifies endpoints for Azure Services based on cloud
.EXAMPLE
   Initialize-GraphEnvironment -Environment $Config.AzureCloud
#>
function Initialize-GraphEnvironment
{
    [CmdletBinding()]
    param
    (
        [ValidateSet('AzureCloud', 'AzureUSGovernment')]
        [string] $Environment = 'AzureCloud'
    )
    Write-Verbose  "Setting Graph Environment: $Environment"
    $graphEnvironmentTemplate += switch ($Environment)
    {
        'AzureCloud'
        {
            @{
                GraphUrl = "https://graph.microsoft.com"
                LoginUrl = "https://login.microsoftonline.com"      
            }
        }
        'AzureUSGovernment'
        {
            @{
                GraphUrl = "https://graph.microsoft.us"
                LoginUrl = "https://login.microsoftonline.us"      
            }   
        }
        default
        {
            throw New-Object NotImplementedException("Unknown environment name '$Environment'")
        }
    }
    return [pscustomobject]$graphEnvironmentTemplate
}

<#
.Synopsis
    Creates a base64 string of a default JWT header, with certificate information
.DESCRIPTION
    Creates a base64 string of a default JWT header, with certificate information
.EXAMPLE
    Get-AppendedSignature -InputString "base64header.base64payload" -Kid "https://kv.vault.azure.net/keys/abc/xxx" -KeyVaultHeaders @{...}
#>
function Get-AppendedSignature {
    [CmdletBinding()]
 
    param (
        [Parameter(Mandatory = $true)] [String] $InputString,
 
        [Parameter(Mandatory = $true)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )
 
    Process {
        # Hash it with SHA-256:
        $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
        $hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($InputString))
         
        # Use certificate to sign hash
        if($Certificate.PrivateKey) {
            $signature = $Certificate.PrivateKey.SignHash($hash, 'SHA256', [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        } else {
            $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
            $signature = $key.SignHash($hash, 'SHA256', [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        }
         
        # Create full JWT with the signature we got from KeyVault (just append .SIGNATURE)
        return $InputString + "." + [System.Convert]::ToBase64String($signature)
    }
}

<#
.Synopsis
    Creates a base64 string of a default JWT header, with certificate information
.DESCRIPTION
    Creates a base64 string of a default JWT header, with certificate information
.EXAMPLE
    Get-JWTHeader -Certificate $cert
#>
function Get-JWTHeader {
    [CmdletBinding()]
 
    param (
        [Parameter(Mandatory = $true)] $Certificate
    ) 
 
    Process {
        [System.Convert]::ToBase64String(([System.Text.Encoding]::UTF8.GetBytes((
                        [ordered] @{
                            "alg" = "RS256"
                            "kid" = $Certificate.Thumbprint
                            "x5t" = (([System.Convert]::ToBase64String($Certificate.GetCertHash())) -replace '\+','-' -replace '/','_' -replace '=')
                            "typ" = "JWT"
                        } | ConvertTo-Json -Compress
                    )))) -replace "=+$" # Required to remove padding
    }
}

<#
.Synopsis
    Creates a signed JWT of the Payload
.DESCRIPTION
    Creates a signed JWT of the Payload
.EXAMPLE
    Get-SignedJWT -Payload @{sub="abc"} -Certificate $cert
#>
function Get-SignedJWT {
    [CmdletBinding()]
 
    param (
        [Parameter(Mandatory = $true)] [System.Collections.Hashtable] $Payload,
 
        [Parameter(Mandatory = $true)] $Certificate,
 
        [Parameter(Mandatory = $false)] [Boolean] $DoNotAddJtiClaim = $false
    )
 
    Process {
        # Build our JWT header
        $JWTHeader = Get-JWTHeader -Certificate $certificate
 
        # Set EXP to unixtime
        if (!$Payload.ContainsKey("exp")) {
            $Payload["exp"] = [int] ((Get-Date).AddHours(1).ToUniversalTime() - [datetime]'1970-01-01T00:00:00Z').TotalSeconds # Unixtime + 3600
        }
        elseif ($Payload["exp"].GetType().Name -eq "DateTime") {
            $Payload["exp"] = [int] ((Get-Date($Payload["exp"]).ToUniversalTime() - [datetime]'1970-01-01T00:00:00Z').TotalSeconds) # Unixtime
        }
        else {
            $Payload["exp"] = [int] ((Get-Date).AddHours(1).ToUniversalTime() - [datetime]'1970-01-01T00:00:00Z').TotalSeconds # Unixtime + 3600
        }
 
        # Set EXP to unixtime
        if (!$Payload.ContainsKey("nbf")) {
            $Payload["nbf"] = [int] ((Get-Date).ToUniversalTime() - [datetime]'1970-01-01T00:00:00Z').TotalSeconds # Unixtime
        }
        elseif ($Payload["nbf"].GetType().Name -eq "DateTime") {
            $Payload["nbf"] = [int] (Get-Date($Payload["nbf"]).ToUniversalTime()  - [datetime]'1970-01-01T00:00:00Z') # Unixtime
        }
        else {
            $Payload["nbf"] = [int] ((Get-Date).ToUniversalTime() - [datetime]'1970-01-01T00:00:00Z').TotalSeconds # Unixtime
        }
 
        # Add jti if missing
        if (!$Payload.ContainsKey("jti") -and !$DoNotAddJtiClaim) {
            $Payload["jti"] = [guid]::NewGuid().ToString()
        }
 
        # Add iat
        $Payload["iat"] = [int] ((Get-Date).ToUniversalTime() - [datetime]'1970-01-01T00:00:00Z').TotalSeconds # Unixtime
         
        # Build our JWT Payload
        $JWTPayload = $Payload | ConvertTo-Json -Depth 5 -Compress
         
        # Create JWT without signature (base64 of header DOT base64 of payload)
        function ConvertTo-Base64($String) { [System.Convert]::ToBase64String(([System.Text.Encoding]::UTF8.GetBytes($String))) }
        $JWTWithoutSignature = $JWTHeader + "." + ((ConvertTo-Base64 $JWTPayload) -replace "=+$")
         
        Get-AppendedSignature -InputString $JWTWithoutSignature -Certificate $Certificate
    }
}

Export-ModuleMember "Get-GraphRequestRecursive", "Save-ADGroup", "ConvertFrom-Base64JWT", "Test-Configuration", "Get-ADGroupForDeprovisioning", "Initialize-GraphEnvironment","Get-AppendedSignature","Get-JWTHeader", "Get-SignedJWT"
