Function Invoke-ArchiveCerts {

    [cmdletbinding()]
    param()

    begin {
        New-Variable -Option Constant -Name XCN_OID_PKIX_KP_OCSP_SIGNING -Value "1.3.6.1.5.5.7.3.9"
    }

    process {

        $Thumbprints = Get-OcspRevocationConfiguration | 
            Where-Object { $Null -ne $_.SigningCertificate } | 
                ForEach-Object -Process {

            # We load the CA Certificate into an X509Certificate2 Object so that we can call Certificate Properties
            $SigningCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $SigningCertificate.Import($_.SigningCertificate)

            # returning the Thumbprint
            $SigningCertificate.Thumbprint

        }

        Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
            $_.EnhancedKeyUsageList -match $XCN_OID_PKIX_KP_OCSP_SIGNING
        } | ForEach-Object -Process {

            $ThisCertificate = $_

            # Compare the Revocation Configs Thumbprints with this Certificate
            $Thumbprints | ForEach-Object {

                # Go on to the next Object if the Certificate is in use
                If ($_ -match $ThisCertificate.Thumbprint) {
                    Write-Output "Certificate $($ThisCertificate.Thumbprint) is in use and will be kept."
                    continue
                }

            }

            # We should get here only if the Thumbprint was not found in any of the Revocation Configs
            Write-Output "Certificate $($ThisCertificate.Thumbprint) is not in use and will be archived."
            $ThisCertificate.Archived = $True

        }

    }
}