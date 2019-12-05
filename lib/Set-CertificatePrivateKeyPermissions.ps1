Function Set-CertificateKeyPermissions {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [ValidateScript({$_.hasPrivateKey})]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(Mandatory=$False)]
        [System.Security.Principal.SecurityIdentifier]
        $Identifier = $(New-Object System.Security.Principal.SecurityIdentifier(
            [System.Security.Principal.WellKnownSidType]::NetworkServiceSid,
            $Null
            ))
    )

    process {

        # Requires .NET 4.6
        $DotNetVersion = (Get-ItemProperty `
                -Path "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" `
                -ErrorAction SilentlyContinue
                ).Release

        If ($DotNetVersion -lt 393295) {
            Write-Warning -Message "Cannot set Permissions on Private Key for Certificate $($Certificate.Thumbprint)."
            Write-Warning -Message "Setting ACLs on CNG Keys requires at least .NET Framework 4.6."
            Write-Warning -Message "Set Permissions manually: $($Identifier.Translate([System.Security.Principal.NTAccount]).Value) needs Read Permission on the Private Key."
            return
        }

        # Works only on CNG Certificates
        # https://stackoverflow.com/questions/51018834/cngkey-assign-permission-to-machine-key
        Try {
            $PrivateKeyObject = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        }
        Catch {
            Write-Warning -Message "Unable to get Private Key Security Information for Certificate $($Certificate.Thumbprint)."
            Write-Warning -Message "Set Permissions manually: $($Identifier.Translate([System.Security.Principal.NTAccount]).Value) needs Read Permission on the Private Key."
            return
        }

        $NCRYPT_SECURITY_DESCR_PROPERTY = "Security Descr"
        $DACL_SECURITY_INFORMATION = 4

        $CngProperty = $PrivateKeyObject.Key.GetProperty(
            $NCRYPT_SECURITY_DESCR_PROPERTY,
            $DACL_SECURITY_INFORMATION
            )

        $Security = New-Object System.Security.AccessControl.CryptoKeySecurity
        $Security.SetSecurityDescriptorBinaryForm($CngProperty.GetValue())

        $AccessRule = New-Object System.Security.AccessControl.CryptoKeyAccessRule(
            $Identifier,
            [System.Security.AccessControl.CryptoKeyRights]::GenericRead,
            [System.Security.AccessControl.AccessControlType]::Allow
            )

        $Security.AddAccessRule($AccessRule)

        $CngProperty2 = New-Object System.Security.Cryptography.CngProperty(
            $CngProperty.Name,
            $Security.GetSecurityDescriptorBinaryForm(),
            ([System.Security.Cryptography.CngPropertyOptions]::Persist -bor $DACL_SECURITY_INFORMATION)
            )

        $PrivateKeyObject.Key.SetProperty($CngProperty2)

    }

}