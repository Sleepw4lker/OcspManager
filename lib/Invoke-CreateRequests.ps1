Function Invoke-CreateRequests {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $ComputerName = $env:computername
    )

    begin {
        Write-Verbose -Message ("Invoking {0}" -f $MyInvocation.MyCommand.Name)
    }

    process {
    
        Get-OcspRevocationConfiguration -Offline | ForEach-Object -Process {

            $ThisConfig = $_

            # We load the Certificate into an X509Certificate2 Object so that we can call Certificate Properties
            $CaCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $CaCertificate.Import($ThisConfig.CACertificate)

            # Get Subject Key Identifier
            $Ski = $CaCertificate.Extensions.SubjectKeyIdentifier

            # Extract CA Common Name
            # https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2.getnameinfo
            # https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509nametype
            $CaName = $CaCertificate.GetNameInfo(
                [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, 
                $False
                )

            $CsrFileName = "$($Script:Config.Config.CsrPath)\$($ComputerName)-$($CAName.Replace(" ","_"))-$($Ski).csr"

            $Arguments = @{
                CommonName = $ComputerName
                Aki = $Ski
            }

            # Try to grab some Meta Information from the Config.xml
            $MetaInformation = $Script:Config.Config.RevocationConfig | Where-Object {
                $_.Name -eq $ThisConfig.Identifier
            }

            If ($MetaInformation.KspName) {
                Write-Verbose -Message "Key Storage Provider is $($MetaInformation.KspName)"
                $Arguments.Add("Ksp", $MetaInformation.KspName)
            }

            If ($MetaInformation.KeyLength) {
                Write-Verbose -Message "Key Length is $($MetaInformation.KeyLength) Bits"
                $Arguments.Add("KeyLength", $MetaInformation.KeyLength)
            }

            # Create Certificate Request specifying the SKI and write it to a CSR file
            New-OcspSigningCertificateRequest @Arguments | Out-File -Filepath $CsrFileName -Encoding utf8

            Get-ChildItem -Path $CsrFileName

        }

    }

    end {
        Write-Verbose -Message ("Finished {0}" -f $MyInvocation.MyCommand.Name)
    }

}