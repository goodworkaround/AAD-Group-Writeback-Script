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
function Get-ClientCredentialsMSGraphAccessToken {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # AD attribute used for anchoring, will contain the objectid from Azure AD
        [Parameter(Mandatory = $true,
            Position = 0)]
        [string] $ClientID,

        # The OU where all groups will be created and is expected to reside
        [Parameter(Mandatory = $true,
            Position = 1)]
        [string] $EncryptedSecret,

        # AD attribute used for anchoring, will contain the objectid from Azure AD
        [Parameter(Mandatory = $true,
            Position = 2)]
        [string] $TenantID
    )

    Begin {
    }
    Process {
        

      try {

       $Credential = [PSCredential]::new($ClientID, (ConvertTo-SecureString $EncryptedSecret))

	#Create request body
	$body = @{
	    client_id     = $ClientID
	    scope         = "https://graph.microsoft.com/.default"
	    client_secret = $Credential.GetNetworkCredential().Password
	
	    #There different grant_types see here
	    grant_type    = "client_credentials"
	}


         $ErrorVar = $null
         #$_AccessToken = Invoke-RestMethod "https://login.microsoftonline.com/$($TenantID)/oauth2/v2.0/token" -Body "client_id=$($ClientID)&scope=https://graph.microsoft.com/.default&client_secret=$($Credential.GetNetworkCredential().Password)&grant_type=client_credentials" -ContentType "application/x-www-form-urlencoded" -Method Post
	 $_AccessToken = Invoke-RestMethod "https://login.microsoftonline.com/$($TenantID)/oauth2/v2.0/token" -Body $body -ContentType "application/x-www-form-urlencoded" -Method Post
         if ($ErrorVar) {
               Write-Error "Error when getting access token using client credentials: $ErrorVar"
         }
         else {
               Write-Debug "Got access token: $($_AccessToken.access_token)"
               return $_AccessToken.access_token
         }
      }
      catch {
         if($_ -like "*Key not valid for use in specified state*") {
            Write-Error "Error when decrypting client secret. Perhaps it was generated on another computer or as another user? Please use the below code to create a new secret: 
            
            `$r = read-host -assecurestring -prompt 'Type your client secret'
            `$r | convertfrom-securestring | set-clipboard

            "
            
         } else {
            Write-Error "Error when getting access token using client credentials" -Exception $_
         }
      }
    }
    End {
    }
}


Export-ModuleMember "Get-ClientCredentialsMSGraphAccessToken"
