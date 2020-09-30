# Set-ZerologonMitigation
Protect your domain controllers against Zerologon (CVE-2020-1472).

## Usage
After installing the August 2020 security update (or a later cumulative version), just run the script on each of 
your domain controllers.

````powershell
.\Set-ZerologonMitigation.ps1
````

For help, run `Get-Help`: 
````powershell
Get-Help .\Set-ZerologonMitigation.ps1
````

For obvious reasons, this script only supports Microsoft Windows.

