Function Invoke-ArchiveCerts {

    [cmdletbinding()]
    param()

    process {

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
}