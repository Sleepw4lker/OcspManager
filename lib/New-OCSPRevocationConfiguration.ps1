Function New-OCSPRevocationConfiguration {
    
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullorEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $ComputerName = $env:computername,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $ConfigString,

        [Parameter(Mandatory=$True)]
        [ValidateNotNullorEmpty()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $CaCertificate,

        [Parameter(Mandatory=$True)]
        [ValidateNotNullorEmpty()]
        [String[]]
        $Cdp,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $CertificateTemplate,

        [Parameter(Mandatory=$False)]
        [ValidateSet("MD2","MD4","MD5","SHA1","SHA256","SHA384","SHA512")]
        [String]
        $SignatureHashAlgorithm = "SHA1",

        [Parameter(Mandatory=$False)]
        [ValidateRange(5,1440)]
        [int16]
        $RefreshTimeout, # in Minutes

        [Parameter(Mandatory=$False)]
        [Switch]
        $AllowNonce = $False
    )

    begin {
        # https://docs.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-iocspcaconfiguration-get_signingflags
        $OCSP_SF_SILENT 	                        = 0x001 # Acquire a private key silently.
        $OCSP_SF_USE_CACERT 	                    = 0x002 # Use a CA certificate in this configuration for signing an OCSP response. This option is available only if the responder service is installed on the CA computer.
        $OCSP_SF_ALLOW_SIGNINGCERT_AUTORENEWAL 	    = 0x004 # Enable a responder service to automatically transition to a renewed signing certificate.
        $OCSP_SF_FORCE_SIGNINGCERT_ISSUER_ISCA 	    = 0x008 # Force a delegated signing certificate to be signed by the CA.
        $OCSP_SF_AUTODISCOVER_SIGNINGCERT 	        = 0x010 # Automatically discover a delegated signing certificate.
        $OCSP_SF_MANUAL_ASSIGN_SIGNINGCERT 	        = 0x020 # Manually assign a signing certificate.
        $OCSP_SF_RESPONDER_ID_KEYHASH 	            = 0x040 # A responder ID includes a hash of the public key of the signing certificate (default).
        $OCSP_SF_RESPONDER_ID_NAME 	                = 0x080 # A responder ID includes the name of the subject in a signing certificate.
        $OCSP_SF_ALLOW_NONCE_EXTENSION              = 0x100 # Enable NONCE extension to be processed by a responder service.
        $OCSP_SF_ALLOW_SIGNINGCERT_AUTOENROLLMENT   = 0x200 # A responder service can enroll for a signing certificate.

        $SigningFlags = 0x0
    }

    process {

        # https://docs.microsoft.com/en-us/windows/desktop/api/certadm/nn-certadm-iocspcaconfiguration
        # https://www.sysadmins.lv/blog-en/managing-online-responders-ocsp-with-powershell-part-3.aspx
        # https://social.technet.microsoft.com/wiki/contents/articles/12167.ocsp-powershell-script.aspx

        If (Test-OCSPRevocationConfiguration -CaCertificate $CaCertificate -ComputerName $ComputerName) {

            # Get Subject Key Identifier
            $Ski = $CaCertificate.Extensions.SubjectKeyIdentifier

            # Extract CA Common Name
            $CaName = $CaCertificate.GetNameInfo(0, $False)

            Write-Warning "There is already a Configuration defined for CA Certificate $($CaCertificate.Thumbprint) ($CaName, SKI: $Ski). Skipping."
            return

        }

        # Save the desired OcspProperties in a collection object
        $OcspProperties = New-Object -ComObject "CertAdm.OCSPPropertyCollection"

        [void]$OcspProperties.CreateProperty(
            "BaseCrlUrls",
            $Cdp
        )

        [void]$OcspProperties.CreateProperty(
            "RevocationErrorCode",
            0
        )

        # If no Refresh Timeout is specified, the Revocation Configuration will update the CRLs based on their validity periods
        If ($RefreshTimeout) {

            # Sets the refresh interval (time is specified in milliseconds)
            [void]$OcspProperties.CreateProperty(
                "RefreshTimeOut",
                ($RefreshTimeout * 60 * 1000)
            )

        }

        $OcspAdmin = New-Object -ComObject "CertAdm.OCSPAdmin"

        $OcspAdmin.GetConfiguration(
            $ComputerName,
            $True
        )

        # The CreateCAConfiguration method creates a new certification authority (CA) configuration and adds it to the configuration set.
        $NewConfig = $OcspAdmin.OCSPCAConfigurationCollection.CreateCAConfiguration(
            $Name,
            $CaCertificate.GetRawCertData()
        )

        $NewConfig.HashAlgorithm = $SignatureHashAlgorithm

        If ($ConfigString.IsPresent -and $CertificateTemplate.IsPresent) {

            $NewConfig.CAConfig = $ConfigString
            $NewConfig.SigningCertificateTemplate = $CertificateTemplate.Trim()

            # 0x294, Auto-Enroll for Signing Certificate
            $SigningFlags = $SigningFlags -bor $OCSP_SF_ALLOW_SIGNINGCERT_AUTORENEWAL
            $SigningFlags = $SigningFlags -bor $OCSP_SF_AUTODISCOVER_SIGNINGCERT
            $SigningFlags = $SigningFlags -bor $OCSP_SF_RESPONDER_ID_NAME
            $SigningFlags = $SigningFlags -bor $OCSP_SF_ALLOW_SIGNINGCERT_AUTOENROLLMENT
        }
        Else {
            # 0x61, manual Assignment of the Signing Certificate
            $SigningFlags = $SigningFlags -bor $OCSP_SF_SILENT
            $SigningFlags = $SigningFlags -bor $OCSP_SF_MANUAL_ASSIGN_SIGNINGCERT
            $SigningFlags = $SigningFlags -bor $OCSP_SF_RESPONDER_ID_KEYHASH   
        }

        If ($AllowNonce.IsPresent) {
            $SigningFlags = $SigningFlags -bor $OCSP_SF_ALLOW_NONCE_EXTENSION
        }

        $NewConfig.SigningFlags = $SigningFlags

        $NewConfig.ProviderProperties = $OcspProperties.GetAllProperties()
        $NewConfig.ProviderCLSID = "{4956d17f-88fd-4198-b287-1e6e65883b19}"
        $NewConfig.ReminderDuration = 90

        Try {
            # Commit the new configuration to the server
            $OcspAdmin.SetConfiguration(
                $ComputerName,
                $True
            )

            $NewConfig
        }
        Catch {
            # Nothing, yet
        }

    }

}