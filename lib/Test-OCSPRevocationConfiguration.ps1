Function Test-OCSPRevocationConfiguration {
    
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullorEmpty()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $CaCertificate,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $ComputerName = $env:computername
    )

    process {

        Get-OcspRevocationConfiguration -ComputerName $ComputerName | ForEach-Object -Process {

            $ThisConfig = $_

            If ($Null -ne $Name) {
                If ($ThisConfig.Identifier -eq $Name) {
                    return $True
                }
            }

            # We load the CA Certificate into an X509Certificate2 Object so that we can call Certificate Properties
            $ThisCaCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $ThisCaCertificate.Import($ThisConfig.CACertificate)

            If ($ThisCaCertificate.Thumbprint -match $CaCertificate.Thumbprint) {
                return $True
            }

        }

        return $False

    }

}