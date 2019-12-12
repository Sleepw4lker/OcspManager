Function Test-KspPresence {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Ksp
    )

    process {

        # https://github.com/pauldotknopf/WindowsSDK7-Samples/blob/master/security/certservices/certenroll/createsimplecertrequest/CreateSimpleCertRequest.cs

        $CspInformationObject = New-Object -ComObject X509Enrollment.CCspInformation

        # Seems that there is no Enumerate Method or the like...
        # thus we simply try to initialize with the given KSP name...
        # if this does not fail, the KSP seems to be present
        Try {
            $CspInformationObject.InitializeFromName($Ksp)
        }
        Catch {
            return $False
        }

        return $True
    }
}