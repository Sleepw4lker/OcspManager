Function Set-OcspSigningConfiguration {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $ComputerName = $env:computername
    )

    process {

        $OcspAdmin = New-Object -ComObject "CertAdm.OCSPAdmin"

        $OcspAdmin.GetConfiguration(
            $ComputerName,
            $True
            )

        $OcspAdmin.OCSPCAConfigurationCollection | ForEach-Object -Process {

            $ThisConfig = $_

            # We load the CA Certificate into an X509Certificate2 Object so that we can call Certificate Properties
            $CaCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $CaCertificate.Import($ThisConfig.CACertificate)

            If ($ThisConfig.SigningCertificate) {
                # We load the CA Certificate into an X509Certificate2 Object so that we can call Certificate Properties
                $OldSigningCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $OldSigningCertificate.Import($ThisConfig.SigningCertificate)
            }

            # Get Subject Key Identifier
            $Ski = $CaCertificate.Extensions.SubjectKeyIdentifier

            # Get the newest OCSP Signing Certificates
            $NewSigningCertificate = Get-OcspSigningCertificate -Aki $Ski

            If (-not $NewSigningCertificate) {

                Write-Warning -Message "No suitable signing Certificate found for Revocation Configuration $($ThisConfig.Identifier)"

            }
            Else {

                # Replace Signing Certificate only if there was any Change
                If (
                    (-not $ThisConfig.SigningCertificate) -or
                    ($OldSigningCertificate.Thumbprint.ToUpper() -ne $NewSigningCertificate.Thumbprint.ToUpper())
                    ) {

                    # Give Network Service Read Access to the Private Key
                    Set-CertificateKeyPermissions -Certificate $NewSigningCertificate

                    # Assign the Signing Certificate to the Revocation Configuration
                    Write-Output "Assigning Certificate $($NewSigningCertificate.Thumbprint) (expiring on $($NewSigningCertificate.NotAfter)) to Revocation Configuration $($ThisConfig.Identifier)"
                    $ThisConfig.SigningCertificate = $NewSigningCertificate.RawData

                }

            }

        }

        # Apply Configuration
        # This gets always triggered even though in theory, there might be situations where nothing was changed
        # The Online Responder will reload the configuration only if there actually was a change
        Write-Verbose -Message "Applying Changes to Configuration"
        $OcspAdmin.SetConfiguration(
            $ComputerName,
            $True
        )

    }

}