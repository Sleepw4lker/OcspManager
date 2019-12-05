
NAME
    OcspManager.ps1
    
SYNOPSIS
    Helper for OCSP Responders requiring manual Certificate Configuration, e.g. due to a DMZ Topology.
    Required Parameters are defined within a Config.XML File in the Script Directory.
    
    
SYNTAX
    OcspManager.ps1 [-CreateRequests] [<CommonParameters>]
    
    OcspManager.ps1 [-CreateRevocationConfigs] [<CommonParameters>]
    
    OcspManager.ps1 [-InstallCerts] [<CommonParameters>]
    
    OcspManager.ps1 [-UpdateRevocationConfigs] [<CommonParameters>]
    
    OcspManager.ps1 [-ArchiveCerts] [<CommonParameters>]
    
    OcspManager.ps1 [-ShowConfig] [<CommonParameters>]
    
    
DESCRIPTION
    

PARAMETERS
    -CreateRevocationConfigs [<SwitchParameter>]
        1st Step. Creates Revocation Configurations out of what is defined in the Config.xml.
        
    -CreateRequests [<SwitchParameter>]
        2nd Step. Reads the current OCSP Configuration and creates Certificate Signing Requests (CSRs) for each CA Certificate.
        Applies the Authority Key Identifier (AKI) Extension to the Certificate Request, as a Microsoft CA may have more than one Private Key.
        
    -InstallCerts [<SwitchParameter>]
        3rd Step. After the Certificates have been issued by the respective CAs, install all of them on the local machine.
        
    -UpdateRevocationConfigs [<SwitchParameter>]
        4th Step. Update all OCSP Revocation Configurations found on the machine.
        Searches for the newest (latest Issuance Date) Signing Certificate for each CA/AKI Combination and applies the Signing Certificate to the respective Revocation Configuration.
        It also tries to assign Private Key Permissions to the Certificate Private Key Objects for the OCSP Responder.
        
    -ArchiveCerts [<SwitchParameter>]
        5th Step. Identifies Signing Certificates that are not in use and sets the Archive Bit on them so that they disappear from the Certificate Store.
        WARNING: Before running this, ensure that all Revocation Configs have a current Signing Certificate assigned with the -UpdateRevocationConfigs Argument.
        
    -ShowConfig [<SwitchParameter>]
        Prints the current Configuration. A Helper to ensure the Config.xml File is as desired.
        
    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see 
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216). 
    
REMARKS
    To see the examples, type: "get-help OcspManager.ps1 -examples".
    For more information, type: "get-help OcspManager.ps1 -detailed".
    For technical information, type: "get-help OcspManager.ps1 -full".



