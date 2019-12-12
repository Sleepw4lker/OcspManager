Function Invoke-ReloadRevocationConfigs {

    [CmdletBinding()]
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

        $OcspAdmin.OCSPCAConfigurationCollection | ForEach-Object {

            Write-Output "Triggering Reload for $($_.Identifier)..."

            # As the Modified Argument is read-only it can 
            # only be triggered by changing a configuration property
            # We simply set the Hash Algorithm to the exact same as before
            $_.HashAlgorithm = $_.HashAlgorithm
            #$_.Modified
        }
    
        $OcspAdmin.SetConfiguration(
            $ComputerName,
            $True
        )

        # Restarting the OCSP Application Pool just as the "Refresh Revocation Data" Option in the GUI would
        # Try/Catch is just a Safety net in Case the WebAdministration Module is not present
        Try {
            Import-Module WebAdministration
            Restart-WebAppPool -Name OCSPISAPIAppPool
        }
        Catch {
            Write-Warning "Could not restart the OCSPISAPIAppPool Application Pool as the WebAdministration PowerShell Module seems not to be installed."
        }

    }
}