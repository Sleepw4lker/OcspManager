Function Invoke-DeleteRevocationConfigs {

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
            $Identifier = $_.Identifier
            Write-Output "Deleting $Identifier"
            $OcspAdmin.OCSPCAConfigurationCollection.DeleteCAConfiguration($Identifier)
        }

        $OcspAdmin.SetConfiguration(
            $ComputerName,
            $True
            )
    }
}