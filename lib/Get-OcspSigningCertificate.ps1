Function Get-OcspSigningCertificate {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [ValidatePattern("^[0-9a-fA-F]{40}$")]
        [String]
        $Aki
    )

    process {

        Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
             ($_.EnhancedKeyUsageList -match "1.3.6.1.5.5.7.3.9") -and
             ($_.HasPrivateKey) -and  
             ($_.NotBefore -le (Get-Date)) 
            } | ForEach-Object {

            # Handle the Case the Certificate doesnt have an AKI Extension
            Try {

                # Extract the Authority Key Identifier
                $CertAki = ($_.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.35" }).Format(0)

                # If this Certificates AKI matches the CAs SKI, return it for further processing
                If ($CertAki.ToUpper() -match $Aki.ToUpper()) {
                    $_
                }

            }
            Catch {
                # Nothing, yet. Just do not return anything.
            }

        } | Sort-Object -Property NotBefore -Descending | Select-Object -First 1 # Return the newest one

    }

}