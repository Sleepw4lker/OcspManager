Function Test-XmlSchema {

    # Inspired by...
    # https://knowledge.zomers.eu/PowerShell/Pages/How-to-validate-XML-against-an-XSD-schema-using-PowerShell.aspx
    # https://gist.github.com/DominicCronin/62bcd1f1da993d64f35b16d78b35c3cc/
    # https://stackoverflow.com/questions/822907/how-do-i-use-powershell-to-validate-xml-files-against-an-xsd

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $True)]
        [ValidateScript({Test-Path $_})]
        [String]
        $Path,
       
        [Parameter(Mandatory = $True)]
        [ValidateScript({Test-Path $_})]
        [String]
        $SchemaPath
    )

    # Extract File Name from $Path

    Write-Verbose "Validating $Path against $SchemaPath"

    # Keep count of how many errors there are in the XML file
    # Must be in $Script Scope so that it can be used outside of the Handler later on
    $Script:XmlValidationHelper = 0

    # Perform the XSD Validation
    $XmlReaderSettings = New-Object -TypeName System.Xml.XmlReaderSettings
    $XmlReaderSettings.ValidationType = [System.Xml.ValidationType]::Schema
    $XmlReaderSettings.ValidationFlags = [System.Xml.Schema.XmlSchemaValidationFlags]::ProcessInlineSchema -bor [System.Xml.Schema.XmlSchemaValidationFlags]::ProcessSchemaLocation

    $XmlValidationHandler = [System.Xml.Schema.ValidationEventHandler] {

        # Exception is an XmlSchemaException
        Write-Warning -Message "$($_.Message) in $($Path) at Line $($_.Exception.LineNumber),$($_.Exception.LinePosition)"
        
        $Script:XmlValidationHelper++

    }
    $XmlReaderSettings.add_ValidationEventHandler($XmlValidationHandler)

    $Namespace = $Null
    $XmlReaderSettings.Schemas.Add($Namespace, $SchemaPath) | Out-Null

    # Get the file
    $XmlFile = Get-Item -Path $Path

    $XmlReader = [System.Xml.XmlReader]::Create(
        $XmlFile.FullName,
        $XmlReaderSettings
    )

    While ($XmlReader.Read()) {
        # We do... nothing, actually
    }

    $XmlReader.Close()

    # Verify the results of the XSD validation
    If($Script:XmlValidationHelper -gt 0) {
        # XML is NOT valid
        break
        $False
    }
    Else {
        # XML is valid
        $True
    }

}