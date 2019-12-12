Function Test-KspPresence {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [String]
        $Ksp
    )

    process {

        # https://github.com/pauldotknopf/WindowsSDK7-Samples/blob/master/security/certservices/certenroll/createsimplecertrequest/CreateSimpleCertRequest.cs

        $CspInformationObject = New-Object -ComObject X509Enrollment.CCspInformation
        Try {
            $CspInformationObject.InitializeFromName($Ksp)
        }
        Catch {
            return $False
        }

        return $True
    }
}