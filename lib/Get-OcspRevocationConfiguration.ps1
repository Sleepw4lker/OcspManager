Function Get-OcspRevocationConfiguration {

    [cmdletbinding(DefaultParameterSetName="None")]
    param(
        [Parameter(Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $ComputerName = $env:computername,

        [Parameter(
            ParameterSetName="Offline",
            Mandatory=$False
            )]
        [Switch]
        $Offline = $False,

        [Parameter(
            ParameterSetName="Online",
            Mandatory=$False
            )]
        [Switch]
        $Online = $False
    )

    begin {
        Write-Verbose -Message ("Invoking {0}" -f $MyInvocation.MyCommand.Name)

        # https://docs.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-iocspcaconfiguration-get_signingflags
        
        # Automatically discover a delegated signing certificate.
        New-Variable -Option Constant -Name OCSP_SF_AUTODISCOVER_SIGNINGCERT -Value 0x010

        # Manually assign a signing certificate.
        New-Variable -Option Constant -Name OCSP_SF_MANUAL_ASSIGN_SIGNINGCERT -Value 0x020
    }

    process {

        $OcspAdmin = New-Object -ComObject "CertAdm.OCSPAdmin"

        $OcspAdmin.GetConfiguration(
            $ComputerName,
            $True
            )

        If ($Offline.IsPresent) {
            $OcspAdmin.OCSPCAConfigurationCollection | Where-Object {
                ($_.SigningFlags -band $OCSP_SF_MANUAL_ASSIGN_SIGNINGCERT) -eq $OCSP_SF_MANUAL_ASSIGN_SIGNINGCERT
            }
        }
        ElseIf ($Online.IsPresent) {
            $OcspAdmin.OCSPCAConfigurationCollection | Where-Object {
                ($_.SigningFlags -band $OCSP_SF_AUTODISCOVER_SIGNINGCERT) -eq $OCSP_SF_AUTODISCOVER_SIGNINGCERT
            }
        }
        Else {
            $OcspAdmin.OCSPCAConfigurationCollection
        }

    }

    end {
        Write-Verbose -Message ("Finished {0}" -f $MyInvocation.MyCommand.Name)
    }

}