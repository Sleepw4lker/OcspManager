Function Set-CertificateKeyPermissions {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [ValidateScript({$_.hasPrivateKey})]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [Parameter(Mandatory=$False)]
        [System.Security.Principal.SecurityIdentifier]
        $Identifier = $(New-Object System.Security.Principal.SecurityIdentifier(
            [System.Security.Principal.WellKnownSidType]::NetworkServiceSid,
            $Null
            )
        )
    )

    begin {
        New-Variable -Option Constant -Name NCRYPT_SECURITY_DESCR_PROPERTY -Value "Security Descr"
        New-Variable -Option Constant -Name DACL_SECURITY_INFORMATION -Value 4
        New-Variable -Option Constant -Name DotNetFX46 -Value 393295
    }

    process {
        
        # https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
        $InstalledDotNetFXVersion = (Get-ItemProperty `
                -Path "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" `
                -ErrorAction SilentlyContinue
                ).Release

        If ($InstalledDotNetFXVersion -lt $DotNetFX46) {
            Write-Warning -Message "Cannot set Permissions on Private Key for Certificate $($Certificate.Thumbprint)."
            Write-Warning -Message "Setting ACLs on CNG Keys requires at least .NET Framework 4.6."
            Write-Warning -Message "Set Permissions manually: $($Identifier.Translate([System.Security.Principal.NTAccount]).Value) needs Read Permission on the Private Key."
            return
        }

        # Requires .NET 4.6
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

        Write-Verbose "Granting Read Permissions on Private Key of Certificate $($Certificate.Thumbprint) to $($Identifier.Translate([System.Security.Principal.NTAccount]).Value)"
        
        Try {
            $PrivateKeyObject.Key.SetProperty($CngProperty2)
        }
        Catch {
            Write-Warning -Message "Unable to set Private Key Security Information for Certificate $($Certificate.Thumbprint)."
            Write-Warning -Message "Set Permissions manually: $($Identifier.Translate([System.Security.Principal.NTAccount]).Value) needs Read Permission on the Private Key."
            return
        }

    }

}