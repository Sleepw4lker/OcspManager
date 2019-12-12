Function Invoke-Deploy {

    [cmdletbinding()]
    param()

    process {

        Write-Output "Installing Server Roles..."

        Install-WindowsFeature `
            -Name Web-Server `
            -IncludeManagementTools

        Install-WindowsFeature `
            -Name ADCS-Online-Cert `
            -IncludeManagementTools

        # The two above statements can be run without error even when the role is present
        # However, the below one can only be run if the role hast not yet been configured
        Try {
            Install-AdcsOnlineResponder -Force
        }
        Catch {
            # We assume it is already configured
        }

        # SafeNet HSM require the OCSP Responder to run as the Local SYSTEM Account instead of the NETWORK SERVICE Account
        If (Test-KspPresence -Ksp "SafeNet Key Storage Provider") { 
            Get-CimInstance -ClassName Win32_Service -Filter "name='OcspSvc'" |
                Invoke-CimMethod -Name Change -Arguments @{StartName="LocalSystem"}
            Restart-Service OcspSvc
        }

        Write-Output "Enabling Firewall Rules..."

        Enable-NetFirewallRule `
            -Name "IIS-WebServerRole-HTTP-In-TCP"
        Enable-NetFirewallRule `
            -Name "IIS-WebServerRole-HTTPS-In-TCP"
        Enable-NetFirewallRule `
            -Name "Microsoft-Windows-OnlineRevocationServices-OcspSvc-DCOM-In"
        Enable-NetFirewallRule `
            -Name "Microsoft-Windows-CertificateServices-OcspSvc-RPC-TCP-In"
        Enable-NetFirewallRule `
            -Name "Microsoft-Windows-OnlineRevocationServices-OcspSvc-TCP-Out"

        Write-Output "Creating Revocation Configurations..."

        Invoke-DeleteRevocationConfigs
        Invoke-CreateRevocationConfigs

        Write-Output "Creating Certificate Requests..."

        Invoke-CreateRequests
        
    }
}