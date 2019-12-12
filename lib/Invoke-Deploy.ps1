Function Invoke-Deploy {

    [cmdletbinding()]
    param()

    begin {
        Write-Verbose -Message ("Invoking {0}" -f $MyInvocation.MyCommand.Name)

        New-Variable -Option Constant -Name ALLOW_INTERACT_WITH_DESKTOP -Value 0x100
    }

    process {

        If ((Get-WindowsFeature -Name ADCS-Online-Cert).InstallState -eq "UninstallPending") {
            Write-Warning "Uninstallation of the Online Responder Role was not yet finished. Aborting."
            return
        }

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
        # https://safenet.gemalto.com/resources/integration-guide/data-protection/Encryption/Microsoft-OCSP-SafeNetLunaHSM-IntegrationGuide-RevR/
        If ($Script:Config.Config.RevocationConfig | Where-Object {
            $_.KspName.ToUpper() -eq $("SafeNet Key Storage Provider").ToUpper()
        }) {

            Write-Verbose -Message "Applying Workaround for SafeNet Key Storage Provider"

            Get-CimInstance -ClassName Win32_Service -Filter "name='OcspSvc'" |
                Invoke-CimMethod -Name Change -Arguments @{StartName="LocalSystem"}

            # Configuring the Service to allow Interaction with the Desktop
            $OcspSvcRegKey = Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\OcspSvc

            If (-not ($OcspSvcRegKey.GetValue('Type') -bor $ALLOW_INTERACT_WITH_DESKTOP) -eq $ALLOW_INTERACT_WITH_DESKTOP) {
                Set-ItemProperty $OcspSvcRegKey.PSPath `
                    -Name Type `
                    -Value ($OcspSvcRegKey.GetValue('Type') -bor $ALLOW_INTERACT_WITH_DESKTOP)
            }

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
        Invoke-UpdateRevocationConfigs

        Write-Output "Creating Certificate Requests..."

        Invoke-CreateRequests
        
    }

    end {
        Write-Verbose -Message ("Finished {0}" -f $MyInvocation.MyCommand.Name)
    }
}