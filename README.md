# Powershell-Security-Tools
A module for Powershell security tools

The below packages are currently still in development, it is not recommended to use in a production
environment. 

Current packages:

# LightweightSecrets - Version 0.10 #
The goal of this package is to discourage the practice of running Powershell sessions as an Administrator 
by making it easier to import credentials that can be used to invoke scripts. The credentials are stored 
locally and encrypted, there is never a plain text version either in memory or on the disk.

It is designed to be lighter weight and easier to use than the SecretManagement or SecretStore modules.

It uses .Net to encrypt and securely store credentials so Powershell (or any .Net application does not
need to be run exclusively as an administrator. This could be extended to web credentials or non-Windows credentials
in the future as well.


# SecurityTools - Version 0.10 #
A package of general tools and functions related to security using Powershell including file encryption and decryption,
testing if the user of a script is an Administrator, or generating random passphrases.
