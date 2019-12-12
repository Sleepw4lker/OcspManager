Function Invoke-Decommission {

    [CmdletBinding()]
    param()

    process {
        Invoke-DeleteRevocationConfigs
        Remove-WindowsFeature -Name ADCS-Online-Cert
    }
}