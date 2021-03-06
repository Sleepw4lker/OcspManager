
NAME
    OcspManager.ps1
    
SYNOPSIS
    Helper for OCSP Responders requiring manual Certificate Configuration, e.g. due to a DMZ Topology.
    Required Parameters are defined within a Config.XML File in the Script Directory.
    
    
SYNTAX
    OcspManager.ps1 [<CommonParameters>]
    
    OcspManager.ps1 -CreateRevocationConfigs [<CommonParameters>]
    
    OcspManager.ps1 -CreateRequests [<CommonParameters>]
    
    OcspManager.ps1 -InstallCerts [<CommonParameters>]
    
    OcspManager.ps1 -UpdateRevocationConfigs [<CommonParameters>]
    
    OcspManager.ps1 -ArchiveCerts [<CommonParameters>]
    
    OcspManager.ps1 -UnArchiveCerts [<CommonParameters>]
    
    OcspManager.ps1 -DeleteCerts [<CommonParameters>]
    
    OcspManager.ps1 -Deploy [<CommonParameters>]
    
    OcspManager.ps1 -Decommission [<CommonParameters>]
    
    OcspManager.ps1 -DeleteRevocationConfigs [<CommonParameters>]
    
    OcspManager.ps1 -ReloadRevocationConfigs [<CommonParameters>]
    
    OcspManager.ps1 -ShowConfig [<CommonParameters>]
    
    
DESCRIPTION
    

PARAMETERS
    -CreateRevocationConfigs [<SwitchParameter>]
        1st Step. Creates Revocation Configurations out of what is defined in the Config.xml.
        Can also create "Online" Configurations for Auto-Enrolled Signing Certificates.
        
    -CreateRequests [<SwitchParameter>]
        2nd Step (Only applies for "Offline" Configurations).
        Reads the current OCSP Configuration and creates Certificate Signing Requests (CSRs) for each CA Certificate.
        Applies the Authority Key Identifier (AKI) Extension to the Certificate Request, as a Microsoft CA may have more than one Private 
        Key.
        
    -InstallCerts [<SwitchParameter>]
        3rd Step (Only applies for "Offline" Configurations).
        After the Certificates have been issued by the respective CAs, install all of them on the local machine.
        
    -UpdateRevocationConfigs [<SwitchParameter>]
        4th Step (Only applies for "Offline" Configurations).
        Update all OCSP Revocation Configurations found on the machine.
        Searches for the newest (latest Issuance Date) Signing Certificate for each CA/AKI Combination and applies the Signing Certificate 
        to the respective Revocation Configuration.
        It also tries to assign Private Key Permissions to the Certificate Private Key Objects for the OCSP Responder.
        
    -ArchiveCerts [<SwitchParameter>]
        5th Step. Identifies Signing Certificates that are not in use and sets the Archive Bit on them so that they disappear from the 
        Certificate Store.
        WARNING: Before running this, ensure that all Revocation Configs have a current Signing Certificate assigned with the 
        -UpdateRevocationConfigs Argument.
        
    -UnArchiveCerts [<SwitchParameter>]
        May be used to un-archive previously archived OCSP Signing Certificates. Warning: Un-Archives all Certificates, which may be a lot.
        
    -DeleteCerts [<SwitchParameter>]
        Same as ArchiveCerts, but the Certificates get hard-deleted, including Private Keys, which may be useful when using a HSM with 
        limited Storage Space.
        
    -Deploy [<SwitchParameter>]
        Can be used for a quick OCSP Deployment. Installs and configures the Role, then creates Revocation Configs and Requests, if any.
        Assigns existing Signing Certificates and creates Certificate Signing Requests afterwards.
        
    -Decommission [<SwitchParameter>]
        Can be used to quickly uninstall the OCSP Responder. Deletes all Revocation Configs and uninstalls the Online Responder Role.
        
    -DeleteRevocationConfigs [<SwitchParameter>]
        Removes all currently defined Revocation Configurations.
        
    -ReloadRevocationConfigs [<SwitchParameter>]
        Marks all configured Revocation Configurations as Dirty, causing them to be reloaded.
        Less invasive than an "iisreset" e.g. to trigger Auto-Enrollment for Signing Certificates.
        
    -ShowConfig [<SwitchParameter>]
        Prints the current Configuration that is defined in the Config.XML. A Helper to ensure the file is configured as desired, and 
        validates against the XML Schema.
        
    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see 
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216). 
    
REMARKS
    To see the examples, type: "get-help OcspManager.ps1 -examples".
    For more information, type: "get-help OcspManager.ps1 -detailed".
    For technical information, type: "get-help OcspManager.ps1 -full".



