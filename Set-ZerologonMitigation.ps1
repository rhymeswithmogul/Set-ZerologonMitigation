<#
.NOTES
Mitigate-Zerologon.ps1, version 1.0.6 (2020-09-23)
Copyright (c) 2020 Colin Cogle <colin@colincogle.name>

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version. This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
for more details.  You should have received a copy of the GNU Affero General
Public License along with this program. If not, see <http://gnu.org/licenses/>.

.SYNOPSIS
Forces a domain controller to use secure RPC, to mitigate the Zerologon attack
that's made possible by CVE-2020-1472.

.DESCRIPTION
The Netlogon Remote Protocol (also called MS-NRPC) is an RPC interface that is
used exclusively by domain-joined devices.  MS-NRPC includes an authentication
method and a method of establishing a Netlogon secure channel.   These updates
enforce the specified Netlogon client behavior to use secure RPC with Netlogon
secure channel between member computers and AD DS domain controllers.

This security update addresses the vulnerability by enforcing secure NRPC when
using the Netlogon secure channel in a phased release explained in the Updates
section of the Microsoft support article (Get-Help -Online).  To provide AD DS
forest protection, all DC's must be updated since they will enforce secure RPC
with Netlogon secure channel. This includes read-only domain controllers.

To learn more about the vulnerability, read up on CVE-2020-1472 and the attack
called Zerologon.

.PARAMETER Verbose
Show more output.

.PARAMETER Debug
Show even more output.

.LINK
https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
Param()

# Make sure we're on Windows.  Core is fine.
If (($PSEdition -ne 'Desktop') -or ($PSEdition -eq 'Core' -And -Not $IsWindows)) {
	Throw [System.PlatformNotSupportedException]::new('This script requires Microsoft Windows.')
} Else {
	Write-Verbose 'Good, this is Microsoft Windows.'
}

# Make sure we're on a domain controller.
# Use Get-CimInstance to avoid crashing on PS 6.
$DomainRole = Get-CimInstance -Class Win32_ComputerSystem | Select-Object -ExpandProperty DomainRole
If ($DomainRole -lt 4) {
	Throw [System.PlatformNotSupportedException]::new('This script can only be run on a domain controller.')
} Else {
	Write-Verbose 'Good, this is a domain controller.'
}

# Make sure we have the appropriate update installed.
# Updated for September 2020!
$Updates = @('KB4565349', 'KB4565351', 'KB4566782', 'KB4570333', 'KB4571694',
             'KB4571702', 'KB4571703', 'KB4571719', 'KB4571723', 'KB4571729',
             'KB4571736', 'KB4571744', 'KB4571756', 'KB4577015', 'KB4577021',
             'KB4577032', 'KB4577041', 'KB4577048', 'KB4577051', 'KB4577053',
             'KB4577062', 'KB4577064', 'KB4577066', 'KB4577069', 'KB4577070',
             'KB4577071', 'KB4577427'
)

If ((Get-Hotfix | Where-Object {$_.HotfixID -In $Updates}).Count -eq 0) {
	Throw [System.PlatformNotSupportedException]::new('This server cannot be protected!  Install the August or September 2020 security update, then try this again.  Note that this script was written in September 2020 and cannot check for future updates!')
} Else {
	Write-Verbose 'Good, we have one of the August or September 2020 updates installed.'
}

$Key   = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$Value = 'FullSecureChannelProtection'

If (-Not (Test-Path $Key)) {
	Throw [System.PlatformNotSupportedException]::new('This script can only be run on a domain controller.')
} Else {
	Try {
		$CurrentValue = Get-ItemProperty -Path $Key | Select-Object -ExpandProperty $Value -ErrorAction Stop
		Write-Debug "Current FullSecureChannelProtection value = $CurrentValue"
		If ($CurrentValue -eq 0) {
			Set-ItemProperty -Path $Key -Name $Value -Value 1 
			Write-Output "This domain controller's Netlogon protection was not enforced, but is now enforced."
		} ElseIf ($CurrentValue -eq 1) {
			Write-Output "This domain controller's Netlogon protection was already enforced."
		} Else {
			Set-ItemProperty -Path $Key -Name $Value -Value 1 
			Write-Output "This domain controller's Netlogon protection is now enforced."
		}
	}
	Catch {
		New-ItemProperty -Path $Key -Name $Value -Value 1 -PropertyType DWord | Out-Null
		Write-Output "This domain controller's Netlogon protection is now enforced."
	}
}
