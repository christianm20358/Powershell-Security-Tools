<# Module Level Variables - These variables can be used in any function but are not
 available outside the module

 Style:
    Script level variables begin with a capital letter, function level variables all use lower
    case letters. This is to make the desired scope clearer for the reader, it has no functional
    impact as variables are not case sensitive in Powershell.

    Ex: $ScriptLevelVariable |  $functionLevelVariable

#>

#Sets a default value for the Store and Type parameters
$PSDefaultParameterValues = @{
    "New-SecretStore:Store"    = "default";
    "Get-SecretStore:Store"    = "default";
    "Remove-SecretStore:Store" = "default";
    "New-SecretItem:Store"     = "default";
    "Use-SecretItem:Store"     = "default";
    "Get-SecretItemLog:Store"  = "default";

    "New-SecretItem:Type"      = "Credential";
    "Get-SecretItem:Type"      = "Credential";

}
#There should be no static file paths in any of the functions

# The path to the SecretStore container. This is the entry point of the functions in the script.
[System.IO.FileInfo]$script:EntryPoint = "$env:LOCALAPPDATA\SupportTools\Store"

#Default Secret Type - For now the default and only supported type is a credential
$script:Type = "Credential"

function Test-Administrator {
    #Simple Function to tell if the current user is an admin
    #only returns the value for the user running the script
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

#Test whether the account type is an administrator
$script:isAdmin = Test-Administrator

function New-SecretStore {
    <#
.SYNOPSIS
    Creates a store for the storing secrets. Allows setting a value for the name,
    and allows a choice to keep the store or self destruct after a certain 
    amount of time. The default store is for credentials for use in Powershell scripts.
 
 
.NOTES
    Name: New-SecretStore
    Author: Christian Miller
    Version: 0.10
    DateCreated: 2022-May-12
 
 
.EXAMPLE
    This is an example of a new store that will self destruct.
    New-SecretStore -Store 'Default' -SelfDestruct -Credential Get-Credential

#>
 
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $false,
            Position = 0
        )]
        [string]$Store = 'default',

        [switch] $SelfDestruct, #the default value for a new vault is to not Self Destruct

        [Parameter(
            Mandatory = $false
        )]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]            
        $Credential = $script:Credential

    )

    BEGIN {

        if ($isAdmin) {
            Write-Host "Creating Store for adminstrator account type"
        }

        if ($isAdmin -eq $false) {
            Write-Host "Creating Store for a non-admin account type"
        }

    }

    PROCESS {
        #Check if there is a store with the same name before continuing
        if ((Test-Path "$EntryPoint\$store") -eq $true) {
            Write-Host "A Store with the name '$store' already exists"
            break
        }

        #If there is no Store location a new one will be created
        if ((Test-Path $EntryPoint\$store) -eq $false) {
            "Setting up new Store"
            New-Item -Name $store -Path $EntryPoint -ItemType Directory -ErrorAction Stop
            # TODO Add Self Destruct ability
            if ($SelfDestruct) {
                Remove-SecretStore $store -Confirm:$false
                Write-Host "Creating new temporary Store $store"
            }
        }
    }

    END {
        try {
            $newStore = Get-ChildItem -Path "$EntryPoint\$store"
            ForEach ($item in $newStore) {
                [System.IO.FileInfo]$FilePath = $item.FullName
                Protect-File -Path $FilePath
            }
            #Encrypt both the store and the store container
            [System.IO.FileInfo]$newPath = Join-Path -Path $EntryPoint -ChildPath $store
            ($newPath).Encrypt()
            $EntryPoint.Encrypt()
        }
        catch {
            #Remove-SecretStore $Name -Credential $cred -Confirm:$false
            Write-Host "Unable to encrypt file", "$($_.Exception.Message)"
        }
    }

}

function Get-SecretStore {
    param(
        [Parameter(
            Mandatory = $false,
            Position = 0
        )]
        [SupportsWildcards()]
        [string]$Store = "*",
    
        [Parameter(
            Mandatory = $false
        )]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]            
        $Credential = $script:Credential
    )

    #Returns object of type Io Directory containing the path to store
    #Supports Wildcard characters
    return $outPutObject = Get-Item -Path $EntryPoint\$store
}
function Remove-SecretStore {
    <#
.SYNOPSIS
    Removes a secret Store.
 
 
.NOTES
    Name: Remove-SecretStore
    Author: Christian Miller
    Version: 0.10
    DateCreated: 2022-May-12
 
 
.EXAMPLE
    Remove-SecretStore -Store 'TempStore' -Credential Get-Credential
 
 
#>
 
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
    param(
        [Parameter(
            Mandatory = $false,
            Position = 0
        )]
        [ValidateScript({
                Get-SecretStore -Store $_
            })]
        [string]$Store = 'default',

        [Parameter(
            Mandatory = $false
        )]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]            
        $Credential = $script:Credential

    )

     
    BEGIN {    
        #If there is no Store location throw an error
        if ((Test-Path $EntryPoint\$store) -eq $false) {
            Write-Host "No Store was found with the name: $store"
            break 
        }
    }
 
    PROCESS {
        try {   
            if (Test-Path $EntryPoint\$store) {
                if ($PSCmdlet.ShouldProcess($store, "Remove Store")) {

                    Remove-Item -Path $EntryPoint\$store -Recurse
                }
            }
        }
        catch {
            throw "$($_.Exception.Message)"
        }
    }

    END {
        
    }

}
function New-SecretItem {
    <#
.SYNOPSIS
    Creates a new secret that can be stored in one of your Stores. The
    'Default' store is the default location, a different Store can be 
    specified if desired. Currently the only supported type of storage
    is a credential. 
 
 
.NOTES
    Name: New-SecretItem
    Author: Christian Miller
    Version: 0.10
    DateCreated: 2022-May-12
 
 
.EXAMPLE
    New-SecretItem -Type 'Credential' -Store 'Default' -Credential jdoe
 
 
#>
 
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $false,
            Position = 0
        )]
        [ValidateScript({
                Get-SecretStore -Store $_
            })]
        [string]$Store = 'default', 

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
        )]
        [ValidateSet("Credential")]
        [string]$Type = "Credential",

        [Parameter(
            Mandatory = $true,
            Position = 2
        )]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]            
        $Credential = $script:Credential

    )

    BEGIN {
        if ($isAdmin) {
            Write-Host "Creating new Secret for Administrative user"
        }
    
    }

    PROCESS {
        #Validate a valid Store to write the SecretItem to
        if ((Test-Path (Get-SecretStore $store)) -eq $false) {
            Write-Host "There was no Store found with the name $store"
            break
        }
        else {
            $storePath = (Get-SecretStore $store).FullName
            if ((Test-Path "$storePath\scratch.txt") -eq $false) {
                #Create a new file if one does not already exist.
                New-Item -Path $storePath -ItemType File -Name "scratch.txt"
                $secretPath = "$storePath\scratch.txt"
                Protect-File -Path $secretPath
                Write-Host "Creating new secret"
            }
            if ($null -eq $Credential) {
                Write-Host "No credential object"
                break
            }
            $secretPath = "$storePath\scratch.txt"  
            #Overwrite value if one already exists
            $secureStringText = $Credential.Password | ConvertFrom-SecureString
            $secretClass = [pscustomobject] @{
                UserName   = $Credential.Username
                Secret     = $secureStringText
                SecretType = $Type 
                Time       = (Get-Date -f g)
                Hash       = $Credential.GetHashCode()
            } | Export-Csv -Path $secretPath -NoTypeInformation 
            Write-Host "Successfully Exported Credential"
        }
    }

    END {

    }

}
function Get-SecretItem {
    <#
.SYNOPSIS
    Retrieves a SecretItem from a vault. If no vault is selected the function
    will attempt to retrieve the input credential from the default vault. Credentials
    are returned as a PSCredential object.
 
 
.NOTES
    Name: Use-SecretItem
    Author: Christian Miller
    Version: 0.10
    DateCreated: 2022-May-13
 
 
.EXAMPLE
    Get-SecretItem -Type 'Credential' -Store 'Default' -Credential jdoe

    $ImportedCredential = Get-SecretItem -Store 'default' -user 'adminaccount'
#>
 
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $false,
            Position = 0
        )]
        [ValidateScript({
                Get-SecretStore -Store $_
            })]
        [string]$Store = "default",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
        )]
        [ValidateSet("Credential")]
        [string]$Type = "Credential",

        [Parameter(
            Mandatory = $false,
            Position = 2
        )]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]            
        $Credential = $script:Credential

    )
    try{
    $importedSecret = Import-Csv "$EntryPoint\$store\scratch.txt" -ErrorAction SilentlyContinue
    } catch {
    if ($null -eq $importedSecret) {
        Write-Host "Could not find any secret items"
        break
    }
    }

    $toCred = $importedSecret.Secret | ConvertTo-SecureString
    
    $credObject = New-Object System.Management.Automation.PSCredential($importedSecret.Username, $toCred)
    
    return $credObject
}
function Get-SecretItemLog {
    <#
    .SYNOPSIS
        This script imports information on stored secrets in a given store
    
    
    .NOTES
        Name: Get-SecretItemLog
        Author: Christian Miller
        Version: 1.0
        DateCreated: 2022-May-14
    
    
    .EXAMPLE
        Get-SecretItemLog -Store default
    
    #>

    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $false,
            Position = 0
        )]
        [ValidateScript({
                Get-SecretStore -Store $_
            })]
        [string]$Store = 'default',

        [Parameter(
            Mandatory = $false,
            Position = 2
        )]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]            
        $Credential = $script:Credential
    )
    try {
    $imported = Import-Csv "$EntryPoint\$store\scratch.txt"

    $returnObject = [pscustomobject] @{
        UserName        = $imported.UserName
        "Secret Type"   = $imported.SecretType
        "Time Exported" = $imported.Time
    }

    return $returnObject
    } catch {
    Write-Host "There were no secrets items found"
    break
    }
}
function Remove-SecretItem {
    <#
    .SYNOPSIS
        This function removes a secret item.
    
    
    .NOTES
        Name: Remove-SecretItem
        Author: Christian Miller
        Version: 1.0
        DateCreated: 2022-May-14
    
    
    .EXAMPLE
        Remove-SecretItem -Store default
    
    #>

    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $false,
            Position = 0
        )]
        [ValidateScript({
                Get-SecretStore -Store $_
            })]
        [string]$Store = 'default',

        [Parameter(
            Mandatory = $false,
            Position = 2
        )]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]            
        $Credential = $script:Credential
    )

        BEGIN {    
        #If there is no Store location throw an error
        if ((Test-Path $EntryPoint\$store) -eq $false) {
            Write-Host "No Store was found with the name: $store"
            break 
        }
    }
 
    PROCESS {
        try {   
            if (Test-Path $EntryPoint\$store\scratch.txt) {
                if ($PSCmdlet.ShouldProcess($store, "Remove Secret")) {

                    Remove-Item -Path $EntryPoint\$store\scratch.txt -Recurse
                    Write-Host "Successfully removed secret item."
                }
            }
        }
        catch {
            throw "$($_.Exception.Message)"
        }
    }

    END {
        
    }

}
function Protect-File {
    <#
.SYNOPSIS
    This script enables EFS Encryption on a given file or folder depending on the 
    path that is input. If a directory is specified the entire directory will be
    encrypted.
 
 
.NOTES
    Name: Protect-File
    Author: Christian Miller
    Version: 1.0
    DateCreated: 2022-May-12
 
 
.EXAMPLE
    Protect-File -Path "C:\PlainTextFolder"
 

#>

    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            HelpMessage = "A File Path for encryption must be entered")]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo]$Path,

        [Parameter(
            Mandatory = $false
        )]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]            
        $Credential
    )

    BEGIN {
        #$ErrorActionPreference = 'Stop'
    }

    PROCESS {
        try {
            $Path.Encrypt()
        }
        catch {
            throw "$($_.Exception.Message)"
        }
    }

    END {

    }    
}
function Unprotect-File {
    <#
.SYNOPSIS
    This script disables EFS Encryption on a given file or folder depending on the 
    path that is input. If a directory is specified the entire directory will be
    decrypted.
 
 
.NOTES
    Name: Unprotect-File
    Author: Christian Miller
    Version: 0.10
    DateCreated: 2022-May-12
 
 
.EXAMPLE
    Unprotect-File -Path "C:\PlainTextFolder"
 

#>
 
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            HelpMessage = "A File Path for decryption must be specified",
            ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo]$Path,

        [Parameter(
            Mandatory = $false
        )]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]            
        $Credential
    )

    BEGIN {
        $ErrorActionPreference = 'Stop'
    }

    PROCESS {
        try {
            $Path.Decrypt()
        }
        catch {
            throw "$($_.Exception.Message)"
        }
    }

    END {

    }    
}


if (!(Test-Path "$script:EntryPoint\default")) {
    New-SecretStore
    Write-Host "New 'default' store created"
    Write-Host "If you would like to create a new secret Item, use the command: New-SecretItem -Store default -Credential 'your_username'"
}