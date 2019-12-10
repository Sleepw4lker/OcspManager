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

    $Script:Config.Config.RevocationConfig | ForEach-Object -Process {

        $CaCertFileName = "$($Script:Config.Config.CaCerPath)\$($_.CaCertFile)"

        If (-not (Test-Path -Path $CaCertFileName)) {

            Write-Warning -Message "Could not find $CaCertFileName. Skipping."

        }
        Else {

            # Load the Certificate from File
            $CaCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $CaCertificate.Import($CaCertFileName)

            # Get Subject Key Identifier
            $Ski = $CaCertificate.Extensions.SubjectKeyIdentifier

            # Extract CA Common Name
            $CaName = $CaCertificate.GetNameInfo(0, $False)

            # Create the Revocation Configuration if not already present, and return its Identifier to show we did anything
            New-OCSPRevocationConfiguration `
                -Name "$CaName (AKI: $Ski)" `
                -CaCertificate $CaCertificate `
                -Cdp $_.Cdp | Select-Object -Property Identifier

        }

    }

}

If ($CreateRequests.IsPresent) {

    New-OcspSigningCertificateRequests

}

If ($InstallCerts.IsPresent) {

    Get-ChildItem $Script:Config.Config.CerPath | Where-Object { $_.Extension -in ".cer",".crt",".pem",".der" } | ForEach-Object -Process {

        $File = $_

        Try {
            # Load the Certificate File, get the Thumbprint to check if it is already present
            $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $Certificate.Import($File.FullName)
        }
        Catch {
            Write-Warning -Message "File $($File.Name) is not a Certificate."

            # Exit the Loop, continue with next Element
            # This will cause the Code below to not be executed, thus the Certificate File will not be deleted
            continue
        }

        If (Test-Path -Path Cert:\LocalMachine\My\$($Certificate.Thumbprint)) {

            Write-Warning -Message "Certificate $($File.Name) ($($Certificate.Thumbprint)) is already installed, skipping."

        }
        Else {

            # Would like to migrate this to native Code, but it works for now
            Try {
                certreq -accept $File.FullName
            }
            Catch {
                Write-Warning -Message "Could not install Certificate File $($File.Name)"

                # Exit the Loop, continue with next Element
                # This will cause the Code below to not be executed, thus the Certificate File will not be deleted
                continue
            }

        }

        Remove-Item -Path $File.FullName
    }

}

If ($UpdateRevocationConfigs.IsPresent) {

    Set-OcspSigningConfiguration

}

If ($ArchiveCerts.IsPresent) {

    $RevocationConfig = Get-OcspRevocationConfiguration

    Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
        $_.EnhancedKeyUsageList -match "1.3.6.1.5.5.7.3.9"
    } | ForEach-Object -Process {

        $ThisCertificate = $_
        $IsInUse = $False

        $RevocationConfig | ForEach-Object {

            $ThisConfig = $_

            # We load the CA Certificate into an X509Certificate2 Object so that we can call Certificate Properties
            $SigningCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $SigningCertificate.Import($ThisConfig.SigningCertificate)

            If ($SigningCertificate.Thumbprint -match $ThisCertificate.Thumbprint) {
                $IsInUse = $True
                Write-Output "Certificate $($ThisCertificate.Thumbprint) is in use by Config $($ThisConfig.Identifier) and will be kept."
            }

        }

        If ($False -eq $IsInUse) {
            $_.Archived = $True
            Write-Output "Certificate $($ThisCertificate.Thumbprint) is not in use and will be archived."
        }

    }

}

If ($ShowConfig.IsPresent) {

    $Script:Config.Config | Format-List

    return

}