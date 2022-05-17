function Test-Administrator {
    #Simple Function to tell if the current user is an admin as
    #only returns the value for the user running the script
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    #returns $true or $false
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
    Version: 0.10
    DateCreated: 2022-May-12
 
 
.EXAMPLE
    Protect-File -Path "C:\PlainTextFolder"
 

#>

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
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
        if (!(Test-Path $Path)) {
            Write-Host "File path could not be resolved"
            $Path
            break
        }
    }

    PROCESS {
        try {
            if ($PSCmdlet.ShouldProcess($path, "Encrypt File")) {
                $Path.Encrypt()
            }
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
 
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
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
        if (!(Test-Path $Path)) {
            Write-Host "File path could not be resolved"
            $path
            break
        }
    }

    PROCESS {
        try {
            if ($PSCmdlet.ShouldProcess($path, "Decrypt File")) {
                $path.Decrypt()
            }
        }
        catch {
            throw "$($_.Exception.Message)"
        }
    }

    END {
        Write-Host "Successfully decrypted: $path"
    }    
}

function New-Passphrase {
    <#
.SYNOPSIS
    This script generates a random passphrase using a wordlist from MIT of the most common words.
    Length, special characters, and numbers can be specified. Currently in beta.
 
 
.NOTES
    Name: New-Passphrase
    Author: Christian Miller
    Version: 0.10
    DateCreated: 2022-May-12
 
 
.EXAMPLE
    New-Passphrase -Path "C:\PlainTextFolder"
 

#>    
    #Grab a list of random words
    $wordlist = Invoke-RestMethod -Uri https://www.mit.edu/~ecprice/wordlist.10000


    #Returns a list of the top 10000 words 

    $wordarray = $wordlist.Split('')


    #Password Properties
    $minlength = 16
    $maxlength = 22
    $nonAlphaChars = ("!", "@", "#", "$", "%", "^", "&", "*", "+")
    $numChars = (1,2,3,4,5,6,7,8,9,0)


    #Get random words
    [array]$randomwords = @($wordarray.Where({$_ -ne ""}) | Get-Random -Count 3)
    $formattedrwords = [string]::Join('-',$randomwords)
    $randomchars = $nonAlphaChars.Where({$_ -ne ""}) | Get-Random -Count 1
    $randomNums = $numChars.Where({$_ -ne ""}) | Get-Random -Count 1


    do {
            [array]$randomwords = @($wordarray.Where({$_ -ne ""}) | Get-Random -Count 3)
            $formattedrwords = [string]::Join('-',$randomwords)
            $randomchars = $nonAlphaChars.Where({$_ -ne ""}) | Get-Random -Count 1
            $randomNums = $numChars.Where({$_ -ne ""}) | Get-Random -Count 1

            $password =[string]$formattedrwords + $randomchars + $randomNums
            
    }while(($password.Length -lt $minlength) -or ($password.Length -gt $maxlength))
    
    Write-Output ("Passphrase: " + $password)
}