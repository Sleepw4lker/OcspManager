Function Invoke-Decommission {

    [CmdletBinding()]
    param()

    begin {
        Write-Verbose -Message ("Invoking {0}" -f $MyInvocation.MyCommand.Name)
    }

    process {

        Invoke-DeleteRevocationConfigs

        Remove-WindowsFeature -Name ADCS-Online-Cert

        Remove-Item `
            -Path HKLM:\SYSTEM\CurrentControlSet\Services\OCSPSvc\Responder `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue

        Disable-NetFirewallRule `
            -Name "Microsoft-Windows-OnlineRevocationServices-OcspSvc-DCOM-In"
        Disable-NetFirewallRule `
            -Name "Microsoft-Windows-CertificateServices-OcspSvc-RPC-TCP-In"
        Disable-NetFirewallRule `
            -Name "Microsoft-Windows-OnlineRevocationServices-OcspSvc-TCP-Out"

    }

    end {
        Write-Verbose -Message ("Finished {0}" -f $MyInvocation.MyCommand.Name)
    }
}