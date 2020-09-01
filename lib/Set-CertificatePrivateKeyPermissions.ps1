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
        Write-Verbose -Message ("Invoking {0}" -f $MyInvocation.MyCommand.Name)
    
        New-Variable -Option Constant -Name NCRYPT_SECURITY_DESCR_PROPERTY -Value "Security Descr"
        New-Variable -Option Constant -Name DACL_SECURITY_INFORMATION -Value 4
        New-Variable -Option Constant -Name DotNetFX46 -Value 393295
    }
    
    process {
    
        # This property is only present on CSP Keys, we use it to determine if this is a CSP or KSP Key, which are handled differently
        If ($null -ne $Certificate.PrivateKey.CspKeyContainerInfo.CryptoKeySecurity) {
    
            # Probably a CSP Key
            Write-Verbose "Certificate $($Certificate.Thumbprint) seems to have a CSP Key"
    
            $AccessRule = New-Object System.Security.AccessControl.CryptoKeyAccessRule(
                $Identifier.Translate([System.Security.Principal.NTAccount]).Value,
                'GenericRead',
                'Allow'
                )
    
            If ($Certificate.PSPath.Contains("LocalMachine")) {
                $CertificateStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
            }
            Else {
                $CertificateStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","CurrentUser")
            }
            
            # Open Certificate store as read/write
            $CertificateStore.Open("ReadWrite")
    
            # Look up the certificate's reference object in the store
            $CertificateObject = $CertificateStore.Certificates | Where-Object { $_.Thumbprint -eq $Certificate.Thumbprint }
    
            # Create new CSP parameter object based on existing certificate provider and key name
            $NewCspParameters = New-Object System.Security.Cryptography.CspParameters(
                $CertificateObject.PrivateKey.CspKeyContainerInfo.ProviderType, 
                $CertificateObject.PrivateKey.CspKeyContainerInfo.ProviderName, 
                $CertificateObject.PrivateKey.CspKeyContainerInfo.KeyContainerName
                )
    
            # Set flags and key security based on existing cert
            $NewCspParameters.Flags = "UseExistingKey","UseMachineKeyStore"
            $NewCspParameters.CryptoKeySecurity = $CertificateObject.PrivateKey.CspKeyContainerInfo.CryptoKeySecurity
            $NewCspParameters.KeyNumber = $CertificateObject.PrivateKey.CspKeyContainerInfo.KeyNumber
    
            # Add access rule to CSP object
            $NewCspParameters.CryptoKeySecurity.AddAccessRule($AccessRule)
    
            Write-Verbose "Granting Read Permissions on Private Key of Certificate $($Certificate.Thumbprint) to $($Identifier.Translate([System.Security.Principal.NTAccount]).Value)"
            
            Try {
                # Create new CryptoServiceProvider object which updates Key with CSP information created/modified above
                [void](New-Object System.Security.Cryptography.RSACryptoServiceProvider($NewCspParameters))
            }
            Catch {
                Write-Warning -Message "Unable to set Private Key Security Information for Certificate $($Certificate.Thumbprint)."
                Write-Warning -Message "Set Permissions manually: $($Identifier.Translate([System.Security.Principal.NTAccount]).Value) needs Read Permission on the Private Key."
                return
            }
    
            # Close certificate store
            $CertificateStore.Close() 
    
        }
        Else {
    
            # Probably a KSP Key
            Write-Verbose "Certificate $($Certificate.Thumbprint) seems to have a KSP Key"
    
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
    
            # This will fail on CSP Keys
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
    
    end {
        Write-Verbose -Message ("Finished {0}" -f $MyInvocation.MyCommand.Name)
    }

}