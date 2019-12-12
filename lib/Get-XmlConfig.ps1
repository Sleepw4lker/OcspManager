# Should be renamed to a more general File Name - like Get-XmlVerifiedData
# Implement a Switch to ignore Schema Errors?
Function Get-XmlConfig {

    param (
        [Parameter(Mandatory=$True)]
        [ValidateScript({Test-Path $_})]
        [String]
        $Path,

        [Parameter(Mandatory=$False)]
        [ValidateScript({Test-Path $_})]
        [String]
        $SchemaPath,

        [Parameter(Mandatory=$False)]
        [ValidateScript({Test-Path $_})]
        [String]
        $SchemaDirectory
    )

    begin {
        Write-Verbose -Message ("Invoking {0}" -f $MyInvocation.MyCommand.Name)
    }

    process {

        Write-Verbose "Loading Configuration File $Path"

        # If no Schema Path was given, we try to find a Schema File within the XML File
        If (-not $SchemaPath) {

            Try {

                # Trying to extract the Schema Path from the XML File
                $Namespace = @{xsi='http://www.w3.org/2001/XMLSchema-instance'}

                # Clarify what this exactly does
                $locationAttr = Select-Xml `
                    -Path $Path `
                    -Namespace $Namespace `
                    -XPath */@xsi:noNamespaceSchemaLocation
                $SchemaFileBaseName = $($locationAttr.Node."#text")

                If ($SchemaFileBaseName) {

                    # Try to find a Schema File with the given Name in the same Directory as the XML File
                    
                    $SchemaFileNameInXmlDirectory = "$((Get-Item $Path).Directory.FullName)\$SchemaFileBaseName"
                    
                    If (Test-Path $SchemaFileNameInXmlDirectory) {

                        $SchemaPath = $SchemaFileNameInXmlDirectory
                        Write-Verbose "Found inline Schema File $SchemaPath"

                    }
                    Else {

                        # Try to find a Schema File with the given Name in the specified Directory
                    
                        If ($SchemaDirectory) {

                            $SchemaFileNameInGivenDirectory = "$SchemaDirectory\$SchemaFileBaseName"

                            If (Test-Path $SchemaFileNameInGivenDirectory) {
                                # Fallback to conf Directory
                                $SchemaPath = $SchemaFileNameInGivenDirectory
                                Write-Verbose "Found inline Schema File $SchemaPath"
                            }

                        }

                    }
                    
                }

            }
            Catch {
                # Nothing
            }
            Finally {
                # Nothing
            }

        }

        # Use a Schema if explicitly given or found inline
        If ($SchemaPath) {

            # Validating the XML File against the Schema File
            If (Test-XmlSchema -Path $Path -SchemaPath $SchemaPath) {
                # If Schema Validation was successful, load the XML File
                [XML]$Config = Get-Content $Path
            }
            Else {
                # Whadda we goinna do?
                Write-Verbose "Schema Validation failed!"
                return

            }

        }
        Else {

            # Fail when no Schema File is found.
            # Decided to make the function fail instead of loading without a Schema, too dangerous!
            Write-Verbose "No XML Schema File found."
            return

        }

        $Config

    }

    end {
        Write-Verbose -Message ("Finished {0}" -f $MyInvocation.MyCommand.Name)
    }

}