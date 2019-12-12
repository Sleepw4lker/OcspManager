Function Get-OcspSigningCertificate {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [ValidatePattern("^[0-9a-fA-F]{40}$")]
        [String]
        $Aki
    )

    begin {
        Write-Verbose -Message ("Invoking {0}" -f $MyInvocation.MyCommand.Name)

        New-Variable -Option Constant -Name XCN_OID_PKIX_KP_OCSP_SIGNING -Value "1.3.6.1.5.5.7.3.9"
        New-Variable -Option Constant -Name XCN_OID_AUTHORITY_KEY_IDENTIFIER2 -Value "2.5.29.35"
        $Now = Get-Date
    }

    process {

        Write-Verbose -Message "Searching for Certificate with AKI $Aki"

        Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
             ($_.EnhancedKeyUsageList -match $XCN_OID_PKIX_KP_OCSP_SIGNING) -and
             ($_.HasPrivateKey) -and
             ($_.NotBefore -le $Now) -and
             ($_.NotAfter -gt $Now)
        } | ForEach-Object -Process {

            # Handle the Case the Certificate doesnt have an AKI Extension
            Try {

                # Extract the Authority Key Identifier
                $CertAki = ($_.Extensions | Where-Object {
                    $_.Oid.Value -eq $XCN_OID_AUTHORITY_KEY_IDENTIFIER2 
                }).Format(0)

                # If this Certificates AKI matches the CAs SKI, return it for further processing
                If ($CertAki.Replace(" ","").ToUpper() -match $Aki.ToUpper()) {
                    Write-Verbose -Message "Found matching Certificate $($_.Thumbprint)"
                    $_
                }

            }
            Catch {
                # Nothing, yet. Just do not return anything.
            }

        } | Sort-Object -Property NotBefore -Descending | Select-Object -First 1 # Return the newest one

    }

    end {
        Write-Verbose -Message ("Finished {0}" -f $MyInvocation.MyCommand.Name)
    }

}