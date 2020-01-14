Function Invoke-ArchiveCerts {

    [cmdletbinding()]
    param(
        [Parameter(
            Mandatory=$False
        )]
        [Switch]
        $DeleteCerts = $False
    )

    begin {
        Write-Verbose -Message ("Invoking {0}" -f $MyInvocation.MyCommand.Name)
        New-Variable -Option Constant -Name XCN_OID_PKIX_KP_OCSP_SIGNING -Value "1.3.6.1.5.5.7.3.9"
    }

    process {

        $Thumbprints = Get-OcspRevocationConfiguration | 
            Where-Object { $Null -ne $_.SigningCertificate } | 
                ForEach-Object -Process {

            # We load the CA Certificate into an X509Certificate2 Object so that we can call Certificate Properties
            $SigningCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $SigningCertificate.Import($_.SigningCertificate)

            Write-Verbose -Message "Adding $($SigningCertificate.Thumbprint) to List."

            # returning the Thumbprint
            $SigningCertificate.Thumbprint

        }

        $AllCertificates = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
            $_.EnhancedKeyUsageList -match $XCN_OID_PKIX_KP_OCSP_SIGNING
        }

        # Warning: Though ForEach-Object would be the more obvious choice, the continue Statement would the behave differently.
        ForEach ($Certificate in $AllCertificates) {
            
            Write-Verbose -Message "Comparing $($Certificate.Thumbprint) against List of configured OCSP Certificates."

            # Compare the Revocation Configs Thumbprints with this Certificate
            $Thumbprints | ForEach-Object {

                # Go on to the next Object if the Certificate is in use
                If ($_ -match $Certificate.Thumbprint) {
                    Write-Output "Certificate $($Certificate.Thumbprint) is in use and will be kept."
                    continue
                }

            }

            If ($DeleteCerts.IsPresent) {
                # We should get here only if the Thumbprint was not found in any of the Revocation Configs
                Write-Output "Certificate $($Certificate.Thumbprint) is not in use and will be deleted."
                Remove-Item -Path Cert:\LocalMachine\My\$($Certificate.Thumbprint) -DeleteKey
            }
            Else {
                Write-Output "Certificate $($Certificate.Thumbprint) is not in use and will be archived."
                $Certificate.Archived = $True
            }

        }

    }

    end {
        Write-Verbose -Message ("Finished {0}" -f $MyInvocation.MyCommand.Name)
    }
}