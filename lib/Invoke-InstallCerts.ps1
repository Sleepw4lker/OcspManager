Function Invoke-InstallCerts {

    [cmdletbinding()]
    param()

    begin {
        Write-Verbose -Message ("Invoking {0}" -f $MyInvocation.MyCommand.Name)
    }

    process {

        $Files = Get-ChildItem -Path $Script:Config.Config.CerPath | Where-Object { $_.Extension -in ".cer",".crt",".pem",".der" }
        
        # Warning: Though ForEach-Object would be the more obvious choice, the continue Statement would the behave differently.
        ForEach ($File in $Files) {
    
            Try {
                # Load the Certificate File, get the Thumbprint to check if it is already present
                $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $Certificate.Import($File.FullName)
            }
            Catch {
                Write-Warning -Message "File $($File.Name) is not a valid Certificate."
    
                # Exit the Loop, continue with next Element
                # This will cause the Code below to not be executed, thus the Certificate File will not be deleted
                continue
            }
    
            If (Test-Path -Path Cert:\LocalMachine\My\$($Certificate.Thumbprint)) {
    
                Write-Warning -Message "Certificate $($File.Name) ($($Certificate.Thumbprint)) is already installed, skipping."
    
            }
            Else {

                If ($True -eq (Install-IssuedCertificate -Certificate $Certificate)) {
                    
                    Write-Output "Certificate $($File.Name) ($($Certificate.Thumbprint)) was successfully installed."

                    # Give Network Service Read Access to the Private Key - if the service is not running as SYSTEM
                    If ((Get-CimInstance -ClassName Win32_Service -Filter "name='OcspSvc'").StartName -ne "LocalSystem") {
                        Set-CertificateKeyPermissions -Certificate (Get-ChildItem Cert:\LocalMachine\My\$($Certificate.Thumbprint))
                    }
                    
                    Remove-Item -Path $File.FullName
                }
                Else {
                    Write-Warning -Message "Could not install Certificate File $($File.Name)."
                }

            }
        }
    }

    end {
        Write-Verbose -Message ("Finished {0}" -f $MyInvocation.MyCommand.Name)
    }
}