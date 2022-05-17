# LightweightSecrets
A lightweight secret manager in Powershell

The goal of this module is to discourage the practice of running Powershell sessions as an Administrator 
by making it easier to import credentials that can be used to invoke scripts. The credentials are stored 
locally and encrypted, there is never a plain text version either in memory or on the disk.

It is designed to be lighter weight and easier to use than the SecretManagement or SecretStore modules.

It uses .Net to encrypt and securely store credentials so Powershell (or any .Net application does not
need to be run exclusively as an administrator. This could be extended to web credentials or non-Windows credentials
in the future as well.

# How to use #

On the initial import a default vault will automatically be created, so the only command that needs to be run is
```
New-SecretItem -Credential your_username
```
There will be a windows popup requesting the password, after entering the credentials they will be stored locally.

**Using the stored credential**
Credentials can be used with the Get-SecretItem command. This command returns the credentials as a PSCredential object
so it's best when a variable is assigned the value of Get-SecretItem. 
Ex:
$secretCreds = Get-SecretItem

Then you can run commands using this credential. For example, as a non-administrative account attempting the below could give
an error that access was denied:
```
Invoke-Command -ComputerName REMOTECOMPUTER -ScriptBlock {ping google.com}
```
However, if you run:
```
Invoke-Command -ComputerName REMOTECOMPUTER -ScriptBlock {ping google.com} -Credential $secretCreds
```
The command would run successfully as if it was run from an administrator account.
