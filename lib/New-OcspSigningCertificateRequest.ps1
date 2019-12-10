Function New-OcspSigningCertificateRequest {

    [cmdletbinding()]
    param (

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CommonName = "",

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $DnsName,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^[0-9a-fA-F]{40}$")]
        [String]
        $Aki,

        [Parameter(Mandatory=$False)]
        [ValidateScript({$Null -ne (certutil -csplist | find "$($_)")})] # Should be converted to PoSH only, but works for now
        [String]
        $Ksp = "Microsoft Enhanced RSA and AES Cryptographic Provider",

        [Parameter(Mandatory=$False)]
        [ValidateSet(2048,3072,4096)]
        [Int]
        $KeyLength = 2048

    )

    begin {

        New-Variable -Option Constant -Name MachineContext -Value 0x2

        # https://docs.microsoft.com/en-us/windows/desktop/api/certenroll/ne-certenroll-x500nameflags
        # https://docs.microsoft.com/en-us/dotnet/api/microsoft.hpc.scheduler.store.x500nameflags?view=hpc-sdk-5.1.6115
        New-Variable -Option Constant -Name XCN_CERT_NAME_STR_NONE -Value 0
        New-Variable -Option Constant -Name XCN_CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG -Value 0x100000

        # https://blog.css-security.com/blog/creating-a-self-signed-ssl-certificate-using-powershell
        New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_DNS_NAME -Value 3

        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa374936(v=vs.85).aspx
        New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64 -Value 0x1

    }

    process {

        # Creating a new Private Key
        $TargetCertificatePrivateKey = New-Object -ComObject 'X509Enrollment.CX509PrivateKey'
        $TargetCertificatePrivateKey.ProviderName = $Ksp

        # 2 = CA certificate
        # 1 = all others
        $TargetCertificatePrivateKey.KeySpec = 1

        # 1 = Machine Context
        # 0 = User Context
        $TargetCertificatePrivateKey.MachineContext = 1

        # We allow the private Key to be exported
        $TargetCertificatePrivateKey.ExportPolicy = [int]$True

        # Specifying the Key Length of the Private Key
        $TargetCertificatePrivateKey.Length = $KeyLength

        # Creating the Key (Pair)
        $TargetCertificatePrivateKey.Create()

        # Begin Assembling the Certificate Signing Request
        # https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/certificate-request-functions
        $TargetCertificate = New-Object -ComObject 'X509Enrollment.CX509CertificateRequestPkcs10'

        $TargetCertificate.InitializeFromPrivateKey($MachineContext, $TargetCertificatePrivateKey, "")

        # Encode Subject in PrintableString
        $SubjectEncodingFlag = $XCN_CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG

        # Set Certificate Subject Name
        $SubjectDistinguishedName = New-Object -ComObject 'X509Enrollment.CX500DistinguishedName'

        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379394(v=vs.85).aspx
        # $XCN_CERT_NAME_STR_NONE
        $SubjectDistinguishedName.Encode(
            "CN=$($CommonName)",
            $SubjectEncodingFlag
        )

        $TargetCertificate.Subject = $SubjectDistinguishedName

        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]$KeyUsage = "DigitalSignature"

        $KeyUsageExtension = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
        $KeyUsageExtension.InitializeEncode([Int]$KeyUsage)
        $KeyUsageExtension.Critical = $True

        # Adding the Key Usage Extension to the Certificate
        $TargetCertificate.X509Extensions.Add($KeyUsageExtension)

        # Set the Subject Alternative Names Extension if specified as Argument
        If ($DnsName) {

            $SansExtension = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
            $Sans = New-Object -ComObject X509Enrollment.CAlternativeNames

            Foreach ($Entry in $DnsName) {
            
                $SanType = $XCN_CERT_ALT_NAME_DNS_NAME
                # https://msdn.microsoft.com/en-us/library/aa374981(VS.85).aspx
                $SanEntry = New-Object -ComObject X509Enrollment.CAlternativeName
                $SanEntry.InitializeFromString($SanType, $Entry)
                $Sans.Add($SanEntry)

            }
            
            $SansExtension.InitializeEncode($Sans)

            # Adding the Extension to the Certificate
            $TargetCertificate.X509Extensions.Add($SansExtension)

        }
    
        # Set the Authority Key Identifier Extension if specified as Argument
        If ($Aki) {

            $AkiExtension = New-Object -ComObject X509Enrollment.CX509ExtensionAuthorityKeyIdentifier 

            # https://docs.microsoft.com/en-us/windows/desktop/api/certenroll/nf-certenroll-ix509extensionauthoritykeyidentifier-initializeencode
            $AkiExtension.InitializeEncode(
                $XCN_CRYPT_STRING_BASE64, 
                $(Convert-DERToBASE64 -String $Aki)
            )

            # Adding the Extension to the Certificate
            $TargetCertificate.X509Extensions.Add($AkiExtension)

        }

        # Encoding the Certificate Signing Request
        $TargetCertificate.Encode()

        # Enrolling for the Certificate
        $EnrollmentObject = New-Object -ComObject 'X509Enrollment.CX509Enrollment'
        $EnrollmentObject.InitializeFromRequest($TargetCertificate)
        $TargetCertificateCsr = $EnrollmentObject.CreateRequest(0)

        # Return the CSR
        $TargetCertificateCsr

    }

}