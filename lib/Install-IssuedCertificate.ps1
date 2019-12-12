Function Install-IssuedCertificate {

    [cmdletbinding(DefaultParameterSetName="Certificate")]
    param(
        [Parameter(
            ParameterSetName="Certificate",
            Mandatory=$True
            )]
        [ValidateNotNullorEmpty()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [Parameter(
            ParameterSetName="Path",
            Mandatory=$True
            )]
        [ValidateScript({Test-Path -Path $_})]
        [String]
        $Path
    )

    begin {

        Write-Verbose -Message ("Invoking {0}" -f $MyInvocation.MyCommand.Name)

        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x509certificateenrollmentcontext
        New-Variable -Option Constant -Name ContextMachine -Value 0x2

        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-installresponserestrictionflags
        New-Variable -Option Constant -Name AllowNone -Value 0

        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa374936(v=vs.85).aspx
        New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64 -Value 0x1
    }

    process {

        If ($Path) {
            $Certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2
            $SigningCertificate.Import($Path)
        }

        # https://www.sysadmins.lv/blog-en/introducing-to-certificate-enrollment-apis-part-3-certificate-request-submission-and-response-installation.aspx

        $EnrollmentObject = New-Object -ComObject X509Enrollment.CX509Enrollment
        $EnrollmentObject.Initialize($ContextMachine)

        $Response = [Convert]::ToBase64String($Certificate.RawData)
        
        <#
            https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509enrollment-installresponse
            HRESULT InstallResponse(
                InstallResponseRestrictionFlags Restrictions,
                BSTR                            strResponse,
                EncodingType                    Encoding,
                BSTR                            strPassword
            );
        #>
        Try {
            Write-Verbose -Message "Installing Certificate $($Certificate.Thumbprint)..."
            $EnrollmentObject.InstallResponse(
                $AllowNone,
                $Response,
                $XCN_CRYPT_STRING_BASE64,
                [string]::Empty
            )
        }
        Catch {
            return $False
        }

        return $True

    }

    end {
        Write-Verbose -Message ("Finished {0}" -f $MyInvocation.MyCommand.Name)
    }
}