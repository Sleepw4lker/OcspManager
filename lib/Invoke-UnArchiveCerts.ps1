Function Invoke-UnArchiveCerts {

    [cmdletbinding()]
    param()

    begin {
        Write-Verbose -Message ("Invoking {0}" -f $MyInvocation.MyCommand.Name)
        New-Variable -Option Constant -Name XCN_OID_PKIX_KP_OCSP_SIGNING -Value "1.3.6.1.5.5.7.3.9"
    }

    process {

        $MachineStore = Get-Item -Path Cert:\LocalMachine\My

        $MachineStore.Open('ReadWrite,IncludeArchived')

        $MachineStore.Certificates | Where-Object {
            ($_.EnhancedKeyUsageList -match $XCN_OID_PKIX_KP_OCSP_SIGNING) -and
            ($_.Archived -eq $True)
        } | ForEach-Object -Process {

            Write-Output "Certificate $($_.Thumbprint) will be unarchived."
            $_.Archived = $False

        } 

    }

    end {
        Write-Verbose -Message ("Finished {0}" -f $MyInvocation.MyCommand.Name)
    }
}