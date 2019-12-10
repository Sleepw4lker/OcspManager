<#

    .SYNOPSIS
    Helper for OCSP Responders requiring manual Certificate Configuration, e.g. due to a DMZ Topology.
    Required Parameters are defined within a Config.XML File in the Script Directory.

    .PARAMETER CreateRevocationConfigs
    1st Step. Creates Revocation Configurations out of what is defined in the Config.xml.
    
    .PARAMETER CreateRequests
    2nd Step. Reads the current OCSP Configuration and creates Certificate Signing Requests (CSRs) for each CA Certificate.
    Applies the Authority Key Identifier (AKI) Extension to the Certificate Request, as a Microsoft CA may have more than one Private Key.

    .PARAMETER InstallCerts
    3rd Step. After the Certificates have been issued by the respective CAs, install all of them on the local machine.

    .PARAMETER UpdateRevocationConfigs
    4th Step. Update all OCSP Revocation Configurations found on the machine.
    Searches for the newest (latest Issuance Date) Signing Certificate for each CA/AKI Combination and applies the Signing Certificate to the respective Revocation Configuration.
    It also tries to assign Private Key Permissions to the Certificate Private Key Objects for the OCSP Responder.

    .PARAMETER ArchiveCerts
    5th Step. Identifies Signing Certificates that are not in use and sets the Archive Bit on them so that they disappear from the Certificate Store.
    WARNING: Before running this, ensure that all Revocation Configs have a current Signing Certificate assigned with the -UpdateRevocationConfigs Argument.

    .PARAMETER ShowConfig
    Prints the current Configuration. A Helper to ensure the Config.xml File is as desired.

   .Notes
    AUTHOR: Uwe Gradenegger, MSFT

    #Requires -Version 5.1

#>

[cmdletbinding(DefaultParameterSetName="CreateRequests")]
param(
    [Parameter(
        ParameterSetName="CreateRevocationConfigs",
        Mandatory=$False
    )]
    [Switch]
    $CreateRevocationConfigs = $False,

    [Parameter(
        ParameterSetName="CreateRequests",
        Mandatory=$False
    )]
    [Switch]
    $CreateRequests = $False,

    [Parameter(
        ParameterSetName="InstallCerts",
        Mandatory=$False
    )]
    [Switch]
    $InstallCerts = $False,

    [Parameter(
        ParameterSetName="UpdateRevocationConfigs",
        Mandatory=$False
    )]
    [Switch]
    $UpdateRevocationConfigs = $False,

    [Parameter(
        ParameterSetName="ArchiveCerts",
        Mandatory=$False
    )]
    [Switch]
    $ArchiveCerts = $False,

    [Parameter(
        ParameterSetName="ShowConfig",
        Mandatory=$False
    )]
    [Switch]
    $ShowConfig = $False
)

# Print Help if the Script was run without any Parameters
If ($PSBoundParameters.Count -eq 0) {
    Get-Help $MyInvocation.MyCommand.Definition -Detailed
    return
}

# Check if the Script is ran with Elevation
If (-not (
    [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning -Message "Script must be run with Elevation (Run as Administrator)! Aborting." 
    return
}

# Check if we have an OCSP Responder installed on the machine
If ($False -eq (Get-WindowsFeature -Name ADCS-Online-Cert).Installed) {
    Write-Warning -Message "This Script requires the Microsoft Online Responder to be installed on the machine! Aborting."
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

If ($ShowConfig.IsPresent) {

    $Script:Config.Config | Format-List
    return

}