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
function Get-ClientCertificateMSGraphAccessToken {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # AD attribute used for anchoring, will contain the objectid from Entra ID
        [Parameter(Mandatory = $true,
            Position = 0)]
        [string] $ClientID,

        # The OU where all groups will be created and is expected to reside
        [Parameter(Mandatory = $true,
            Position = 1)]
        [string] $Thumbprint,

        # AD attribute used for anchoring, will contain the objectid from Entra ID
        [Parameter(Mandatory = $true,
            Position = 2)]
        [string] $TenantID,

        [Parameter(Mandatory = $true,
            Position = 3)]
        [ValidateNotNull()]
        [string] $LoginUrl,

        [Parameter()]
        [ValidateNotNull()]
        [string] $GraphUrl
    )

    Begin {
    }
    Process {
        try {
            $Certificate = @(
                Get-ChildItem Cert:\LocalMachine\My 
                Get-ChildItem Cert:\CurrentUser\My 
            ) | Where-Object { $_.Thumbprint -eq $Thumbprint } | Select-Object -First 1

            if(!$Certificate) {
                Write-Error "Could not find certificate with thumbprint $Thumbprint" -ErrorAction Stop
            }

            Write-Verbose "Certificate thumbprint: $($Certificate.Thumbprint)"
            Write-Verbose "Certificate subject: $($Certificate.Subject)"
            Write-Verbose "Certificate not valid after: $($Certificate.NotAfter)"
            Write-Verbose "Certificate not valid before: $($Certificate.NotBefore)"

            if(!$Certificate.HasPrivateKey) {
                Write-Error "Certificate does not have private key" -ErrorAction Stop
            }

            $AssertionJWT = Get-SignedJWT -Payload @{
                "aud" = "$LoginUrl/$($TenantID)/oauth2/v2.0/token"
                "iss" = $ClientID
                "sub" = $ClientID
            } -Certificate $Certificate

            #Create request body
            $body = @{
                client_id             = $ClientID
                client_assertion      = $AssertionJWT
                client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                scope                 = "$GraphUrl/.default"
                grant_type            = "client_credentials"
            }

            $ErrorVar = $null
            $_AccessToken = Invoke-RestMethod "$LoginUrl/$($TenantID)/oauth2/v2.0/token" -Body $body -Method Post
            if ($ErrorVar) {
                Write-Error "Error when getting access token using client credentials: $ErrorVar"
            }
            else {
                Write-Debug "Got access token: $($_AccessToken.access_token)"
                return $_AccessToken.access_token
            }
        }
        catch {
            Write-Error "Error when getting access token using client certificate" -Exception $_
        }
    }
    End {
    }
}


Export-ModuleMember "Get-ClientCertificateMSGraphAccessToken"
