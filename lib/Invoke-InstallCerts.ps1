Function Invoke-InstallCerts {

    [cmdletbinding()]
    param()

    process {

        Get-ChildItem $Script:Config.Config.CerPath | Where-Object { $_.Extension -in ".cer",".crt",".pem",".der" } | ForEach-Object -Process {

            $File = $_
    
            Try {
                # Load the Certificate File, get the Thumbprint to check if it is already present
                $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $Certificate.Import($File.FullName)
            }
            Catch {
                Write-Warning -Message "File $($File.Name) is not a Certificate."
    
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
                    Remove-Item -Path $File.FullName
                }
                Else {
                    Write-Warning -Message "Could not install Certificate File $($File.Name)"
                }

            }
        }
    }
}