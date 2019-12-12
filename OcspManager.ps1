<#

    .SYNOPSIS
    Helper for OCSP Responders requiring manual Certificate Configuration, e.g. due to a DMZ Topology.
    Required Parameters are defined within a Config.XML File in the Script Directory.

    .PARAMETER CreateRevocationConfigs
    1st Step. Creates Revocation Configurations out of what is defined in the Config.xml.
    Can also create "Online" Configurations for Auto-Enrolled Signing Certificates.
    
    .PARAMETER CreateRequests
    2nd Step (Only applies for "Offline" Configurations).
    Reads the current OCSP Configuration and creates Certificate Signing Requests (CSRs) for each CA Certificate.
    Applies the Authority Key Identifier (AKI) Extension to the Certificate Request, as a Microsoft CA may have more than one Private Key.

    .PARAMETER InstallCerts
    3rd Step (Only applies for "Offline" Configurations).
    After the Certificates have been issued by the respective CAs, install all of them on the local machine.

    .PARAMETER UpdateRevocationConfigs
    4th Step (Only applies for "Offline" Configurations).
    Update all OCSP Revocation Configurations found on the machine.
    Searches for the newest (latest Issuance Date) Signing Certificate for each CA/AKI Combination and applies the Signing Certificate to the respective Revocation Configuration.
    It also tries to assign Private Key Permissions to the Certificate Private Key Objects for the OCSP Responder.

    .PARAMETER ArchiveCerts
    5th Step. Identifies Signing Certificates that are not in use and sets the Archive Bit on them so that they disappear from the Certificate Store.
    WARNING: Before running this, ensure that all Revocation Configs have a current Signing Certificate assigned with the -UpdateRevocationConfigs Argument.

    .PARAMETER Deploy
    Can be used for a quick OCSP Deployment. Installs and configures the Role, then creates Revocation Configs and Requests, if any.
    Assigns existing Signing Certificates and creates Certificate Signing Requests afterwards.

    .PARAMETER Decommission
    Can be used to quickly uninstall the OCSP Responder. Deletes all Revocation Configs and uninstalls the Online Responder Role.

    .PARAMETER DeleteRevocationConfigs
    Removes all currently defined Revocation Configurations.

    .PARAMETER ReloadRevocationConfigs
    Marks all configured Revocation Configurations as Dirty, causing them to be reloaded.
    Less invasive than an "iisreset" e.g. to trigger Auto-Enrollment for Signing Certificates.

    .PARAMETER ShowConfig
    Prints the current Configuration that is defined in the Config.XML. A Helper to ensure the file is configured as desired, and validates against the XML Schema.

   .Notes
    AUTHOR: Uwe Gradenegger, MSFT

    #Requires -Version 5.1

#>

[cmdletbinding(DefaultParameterSetName="None")]
param(
    [Parameter(
        ParameterSetName="CreateRevocationConfigs",
        Mandatory=$True
    )]
    [Switch]
    $CreateRevocationConfigs = $False,

    [Parameter(
        ParameterSetName="CreateRequests",
        Mandatory=$True
    )]
    [Switch]
    $CreateRequests = $False,

    [Parameter(
        ParameterSetName="InstallCerts",
        Mandatory=$True
    )]
    [Switch]
    $InstallCerts = $False,

    [Parameter(
        ParameterSetName="UpdateRevocationConfigs",
        Mandatory=$True
    )]
    [Switch]
    $UpdateRevocationConfigs = $False,

    [Parameter(
        ParameterSetName="ArchiveCerts",
        Mandatory=$True
    )]
    [Switch]
    $ArchiveCerts = $False,

    [Parameter(
        ParameterSetName="Deploy",
        Mandatory=$True
    )]
    [Switch]
    $Deploy = $False,

    [Parameter(
        ParameterSetName="Decommission",
        Mandatory=$True
    )]
    [Switch]
    $Decommission = $False,

    [Parameter(
        ParameterSetName="DeleteRevocationConfigs",
        Mandatory=$True
    )]
    [Switch]
    $DeleteRevocationConfigs = $False,

    [Parameter(
        ParameterSetName="ReloadRevocationConfigs",
        Mandatory=$True
    )]
    [Switch]
    $ReloadRevocationConfigs = $False,

    [Parameter(
        ParameterSetName="ShowConfig",
        Mandatory=$True
    )]
    [Switch]
    $ShowConfig = $False
)

# Print Help if the Script was run without any Parameters
If ($PSBoundParameters.Count -eq 0) {
    Get-Help $MyInvocation.MyCommand.Definition -Detailed
    return
}

$Script:BaseDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

# Loading all Libary Scripts we depend on
Get-ChildItem -Path "$Script:BaseDirectory\lib" -Filter *.ps1 | ForEach-Object {
    . ($_.FullName)
}

# Import the Config.xml and validate it against a Schema File
$Script:Config = Get-XmlConfig `
    -Path "$($Script:BaseDirectory)\Config.xml" `
    -SchemaPath "$($Script:BaseDirectory)\Config.xsd"

If ($ShowConfig.IsPresent) {
    $Script:Config.Config | Format-List
    $Script:Config.Config.RevocationConfig | Format-List
    return
}

# Ensuring the Script will be run on a supported Operating System
$OS = Get-WmiObject Win32_OperatingSystem
If (($OS.name -notmatch "Server") -or ([int32]$OS.BuildNumber -lt 9200)) {
    Write-Warning -Message "This Script must be run on Windows Server 2012 or newer!"
    return 
}

# Check if the Script is ran with Elevation
If (-not (
    [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning -Message "This Script must be run with Elevation (Run as Administrator)! Aborting." 
    return
}

# This is obviously the only Command that does not require the Online Responder to be installed
If ($Deploy.IsPresent) {
    Invoke-Deploy
}

# Check if we have an OCSP Responder installed on the machine
If (-not (Get-WindowsFeature -Name ADCS-Online-Cert).Installed) {
    Write-Warning -Message "This Script requires the Microsoft Online Responder to be installed on the machine! Aborting."
    return
}

If ($CreateRevocationConfigs.IsPresent) {
    Invoke-CreateRevocationConfigs
}

If ($CreateRequests.IsPresent) {
    Invoke-CreateRequests
}

If ($InstallCerts.IsPresent) {
    Invoke-InstallCerts
}

If ($UpdateRevocationConfigs.IsPresent) {
    Invoke-UpdateRevocationConfigs
}

If ($ArchiveCerts.IsPresent) {
    Invoke-ArchiveCerts
}

If ($Decommission.IsPresent) {
    Invoke-Decommission
}

If ($DeleteRevocationConfigs.IsPresent) {
    Invoke-DeleteRevocationConfigs
}

If ($ReloadRevocationConfigs.IsPresent) {
    Invoke-ReloadRevocationConfigs
}