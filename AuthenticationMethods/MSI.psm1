<#
.Synopsis
   Returns MSI access token
.DESCRIPTION
   Returns MSI access token
.EXAMPLE
   Get-MSIMSGraphAccessToken
#>
function Get-MSIMSGraphAccessToken
{
    [CmdletBinding()]
    [OutputType([string])]
    Param()

    Begin
    {
    }
    Process
    {
        try {
            $ErrorVar = $null
            $_AccessToken = Invoke-RestMethod 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/' -Headers @{Metadata = "true"} -Verbose:$false -ErrorVariable "ErrorVar"
            if($ErrorVar) {
                Write-Error "Error when getting MSI access token: $ErrorVar"
            } else {
                Write-Debug "Got access token: $($_AccessToken.access_token)"
                return $_AccessToken.access_token
            }
        } catch {
            Write-Error "Error when getting MSI access token" -Exception $_
        }
    }
    End
    {
    }
}

Export-ModuleMember -Function "Get-MSIMSGraphAccessToken"