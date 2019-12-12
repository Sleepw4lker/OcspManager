Function Invoke-CreateRequests {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $ComputerName = $env:computername
    )

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

            $CsrFileName = "$($Script:Config.Config.CsrPath)\$($CAName.Replace(" ","_"))-$($Ski).csr"

            # Create Certificate Request specifying the SKI and write it to a CSR file
            New-OcspSigningCertificateRequest `
                -CommonName $ComputerName `
                -Ksp $Script:Config.Config.KspName `
                -Aki $Ski `
                -KeyLength $Script:Config.Config.KeyLength | Out-File -Filepath $CsrFileName -Encoding utf8

            Get-ChildItem -Path $CsrFileName

        }

    }

}