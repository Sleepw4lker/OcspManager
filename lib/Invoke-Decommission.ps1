Function Invoke-Decommission {

    [CmdletBinding()]
    param()

    begin {
        Write-Verbose -Message ("Invoking {0}" -f $MyInvocation.MyCommand.Name)
    }

    process {
        Invoke-DeleteRevocationConfigs

        Disable-NetFirewallRule `
            -Name "Microsoft-Windows-OnlineRevocationServices-OcspSvc-DCOM-In"
        Disable-NetFirewallRule `
            -Name "Microsoft-Windows-CertificateServices-OcspSvc-RPC-TCP-In"
        Disable-NetFirewallRule `
            -Name "Microsoft-Windows-OnlineRevocationServices-OcspSvc-TCP-Out"

        Remove-WindowsFeature -Name ADCS-Online-Cert
    }

    end {
        Write-Verbose -Message ("Finished {0}" -f $MyInvocation.MyCommand.Name)
    }
}