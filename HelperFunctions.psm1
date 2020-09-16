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
function Ensure-ADGroup {
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
        Write-Verbose "Starting Ensure-ADGroup"

        Write-Debug "Getting all groups from destination OU, as this is faster than querying each group one at a time"
        $ADGroupMap = @{}

        Get-ADGroup -SearchBase $DestinationOU -Filter * -Properties members,$ADGroupObjectIDAttribute,displayName,name |
            Where-Object {$_.$ADGroupObjectIDAttribute} |
            ForEach-Object {
                $ADGroupMap[$_.$ADGroupObjectIDAttribute] = $_
            }
    }
    Process {
        Write-Verbose "Processing AADGroup '$($AADGroup.displayName)' ($($AADGroup.id))"
        if(!$ADGroupMap.Contains($AADGroup.id)) {
            Write-Verbose "Creating group '$($AADGroup.displayName)' in AD"
            $ADGroupMap[$AADGroup.id] = New-ADGroup -Name $AADGroup.displayName -DisplayName $AADGroup.displayName -GroupScope Global -GroupCategory Security -Path $DestinationOU -OtherAttributes @{"$($ADGroupObjectIDAttribute)" = $AADGroup.id} | Get-ADGroup -Properties members,$ADGroupObjectIDAttribute,displayName,name
        } else {
            $ADGroup = $ADGroupMap[$AADGroup.id]
            if($AADGroup.displayName -ne $ADGroup.displayName) {
                Write-Verbose "Fixing displayname of AD group: '$($ADGroup.DisplayName)' -> $($AADGroup.displayName)"
                $ADGroup | Set-ADGroup -DisplayName $AADGroup.displayName
            }

            if($AADGroup.displayName -ne $ADGroup.name) {
                Write-Verbose "Fixing name of AD group: '$($ADGroup.name)' -> $($AADGroup.displayName)"
                $ADGroup | Set-ADGroup -Name $AADGroup.displayName
            }
        }
    }
    End {
        Write-Verbose "Ensure-ADGroup finished"
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

Export-ModuleMember "Get-GraphRequestRecursive", "Ensure-ADGroup", "ConvertFrom-Base64JWT"