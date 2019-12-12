Function Invoke-CreateRevocationConfigs {

    [cmdletbinding()]
    param()

    begin {
        Write-Verbose -Message ("Invoking {0}" -f $MyInvocation.MyCommand.Name)
    }

    process {

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
                #$Ski = $CaCertificate.Extensions.SubjectKeyIdentifier
    
                # Extract CA Common Name
                #$CaName = $CaCertificate.GetNameInfo(0, $False)
    
                $Arguments = @{
                    Name = $_.Name # "$CaName (AKI: $Ski)"
                    CaCertificate = $CaCertificate
                    Cdp = $_.Cdp 
                }
    
                If ($_.Type -eq "Online") {
                    $Arguments.Add("ConfigString", $_.ConfigString)
                    $Arguments.Add("CertificateTemplate", $_.CertificateTemplate)
                }
    
                If ($_.DeltaCdp) {
                    $Arguments.Add("DeltaCdp", $_.DeltaCdp)
                }

                If ($_.SignatureHashAlgorithm) {
                    $Arguments.Add("SignatureHashAlgorithm", $_.SignatureHashAlgorithm)
                }
    
                # Create the Revocation Configuration if not already present, and return its Identifier to show we did anything
                New-OCSPRevocationConfiguration @Arguments | Select-Object -Property Identifier
    
            }
        }
    }

    end {
        Write-Verbose -Message ("Finished {0}" -f $MyInvocation.MyCommand.Name)
    }
}