Function Invoke-UpdateRevocationConfigs {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $ComputerName = $env:computername
    )

    begin {
        # https://docs.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-iocspcaconfiguration-get_signingflags

        # Manually assign a signing certificate.
        New-Variable -Option Constant -Name OCSP_SF_MANUAL_ASSIGN_SIGNINGCERT -Value 0x020
    }

    process {

        $OcspAdmin = New-Object -ComObject "CertAdm.OCSPAdmin"

        $OcspAdmin.GetConfiguration(
            $ComputerName,
            $True
            )

        $OcspAdmin.OCSPCAConfigurationCollection | Where-Object {
            ($_.SigningFlags -band $OCSP_SF_MANUAL_ASSIGN_SIGNINGCERT) -eq $OCSP_SF_MANUAL_ASSIGN_SIGNINGCERT
        } | ForEach-Object -Process {

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

            # Get the newest OCSP Signing Certificate
            $NewSigningCertificate = Get-OcspSigningCertificate -Aki $Ski

            If (-not $NewSigningCertificate) {

                Write-Warning -Message "No suitable signing Certificate found for Revocation Configuration $($ThisConfig.Identifier)"

            }
            Else {

                # Replace Signing Certificate only if there was any Change, 
                # or if there is currently no Signing Certificate assigned
                If ((-not $ThisConfig.SigningCertificate) -or
                    ($OldSigningCertificate.Thumbprint.ToUpper() -ne $NewSigningCertificate.Thumbprint.ToUpper())) {

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