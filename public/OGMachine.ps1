##################################################################################################################################
#  OS Region
##################################################################################################################################

<#
.SYNOPSIS
    Get Operating System Version
.DESCRIPTION
    Gets the Operating system Version property from WMI Class Win32_OperatingSystem
.EXAMPLE
    PS C:\> Get-OGOSVersionNT
    Returns the Operating System Version number.
.INPUTS
    N/A
.OUTPUTS
    Returns the Operating System Version number.
.NOTES
    Name:       Get-OGOSVersionNT
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-08-17
    Updated:    -

    Version history:
        1.0.0 - 2021-08-17 Function created
#>
Function Get-OGOSVersionNT {
    [cmdletbinding()]
    $qOS = Get-WMIObject -Query "Select Version from Win32_OperatingSystem"
    ## Get the name of this function and write header
    $arrVersion = ($qOS.Version).Split(".")
    [int]$osVal = ([int]$ArrVersion[0] * 100) + ([int]$ArrVersion[1])
    Write-OGLogEntry -logText "OS Version - $($qOS.Version)" 
    Return $osVal
}

<#
.SYNOPSIS
    Gets MS Office Active Processes and returns them.
.DESCRIPTION
    Gets MS Office Active Processes and returns them.

.EXAMPLE
    PS C:\> Get-OGMSOfficeActiveProcesses
        Returns MS Office Active Processes
            Path -like "*\Microsoft Office\*"
            ProcessName -like "*lync*"
            ProcessName -like "*Outlook"
            ProcessName -like "*OneNote"
            ProcessName -like "*Groove*""
            ProcessName -like "*MSOSync"
            ProcessName -like "*Teams*""
            ProcessName -like "*OneDriv*""
.INPUTS
    N/A
.OUTPUTS
    System.Diagnostics.Process
.NOTES
    Name:       Get-OGMSOfficeActiveProcesses
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-08-17
    Updated:    -

    Version history:
        1.0.0 - 2021-08-17 Function created
#>
Function Get-OGMSOfficeActiveProcesses {
    [cmdletbinding()]
    $ActiveProcesses = Get-Process | Where-Object { (($_.path -like "*\Microsoft Office\*")`
                -or ($_.ProcessName -like "*lync*")`
                -or ($_.ProcessName -like "*Outlook*")`
                -or ($_.ProcessName -like "*OneNote*")`
                -or ($_.ProcessName -like "*Groove*")`
                -or ($_.ProcessName -like "*MSOSync*")`
                -or ($_.ProcessName -like "*Teams*")`
                -or ($_.ProcessName -like "*OneDrive*")) }
    Return $ActiveProcesses
}
##################################################################################################################################
# End OS Region
##################################################################################################################################
##################################################################################################################################
##################################################################################################################################
# Files Folder Region
##################################################################################################################################

<#
.SYNOPSIS
    Gets a Temp File/Folder location.
.DESCRIPTION
    Creates if not found and returns the path of a Temp File/Folder location.
.EXAMPLE
    PS C:\> Get-OGTempStorage -File
    Creates if not found and returns the path of a Temp File/Folder location.
.EXAMPLE
    PS C:\> Get-OGTempStorage
    Creates if not found and returns the path of a Temp File/Folder location.
.PARAMETER File
    Gets a Temp file location.
.PARAMETER Folder
    Gets a Temp folder location.
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    Name:       Get-OGTempStorage
    Author:     Richie Schuster - SCCMOG.com
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-08-24
    Updated:    -

    Version history:
        1.0.0 - 2021-08-24 Function created
#>
function Get-OGTempStorage(){
    [cmdletbinding()]
    param (
        [switch]$File,
        [switch]$Folder
    )
    Do{
        if ($Folder) {
            Write-Verbose "Getting temp Folder path."
            $tempStorage = [System.IO.Path]::GetTempPath()
        }
        elseif ($File) {
            Write-Verbose "Getting temp File path."
            $tempStorage = [System.IO.Path]::GetTempFileName()
        }
        else{
            throw "Please supply switch: File | Folder"
        }
        start-sleep -Milliseconds 300
        $MaxReps++
    }
    Until((test-path $tempStorage)-or($MaxReps -eq 100))
    if($MaxReps -eq 100){
        throw "Creating Temp file/folder timed out."
    }
    else{
        Write-Verbose "Tempstorage location: '$($tempStorage)' "
        return $tempStorage
    }
}

<#
.SYNOPSIS
    Pull a certificate from a file

.DESCRIPTION
    Pulls the certificate from a file and stores it at the root of the script by default.

.PARAMETER File
    Description: Path to file to get Certificate from.

.PARAMETER writeLocation
    Description:    Path to file to get Certificate from.

.PARAMETER certName
    Description:    Name of certificate for saving.

.EXAMPLE
    Get-OGFileCertificate -File "$ENV:temp\myappxpackage.appx"
.EXAMPLE
    Get-OGFileCertificate -File "$ENV:temp\myappxpackage.appx" -writeLocation "$ENV:programData"
.EXAMPLE
    Get-OGFileCertificate -File "$ENV:temp\myappxpackage.appx" -writeLocation "$ENV:programData" -certName "MyCert"

.NOTES
    Name:       Get-OGFileCertificate       
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2020-30-07
    Updated:    -
    
    Version history:
    1.0.0 - (2020-30-07) Function created
    #>
function Get-OGFileCertificate {
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$file,
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]$writeLocation = "$($ScriptRoot)",
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]$certName = "temp_cert"
    )
    $writelocation = "$($writelocation)\$certname.cer"
    #Set file type for export
    $exportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert;
    #Get file signer SignerCertificate
    Try {
        Write-OGLogEntry -LogText "Starting certificate extract attempt from file $($file)."
        $cert = (Get-AuthenticodeSignature $file).SignerCertificate;
        Write-OGLogEntry -LogText "Success extracing certificate details from file $($file)."
        #Write Certificate
        Write-OGLogEntry -LogText "Saving certificate information to file: $($writelocation)"
        [System.IO.File]::WriteAllBytes($("$($writelocation)"), $cert.Export($exportType));
        Write-OGLogEntry -LogText "Success saving certificate information to file: $($writelocation)"
        return $($writelocation), $true
    }
    catch [System.Exception] {
        Write-OGLogEntry -LogText "Failed to extract certificate from file $($file). Error Message: $($_.Exception.Message)" -logType Error
        return $false
    }
}

<#
.SYNOPSIS
    Invoke-OGImportCertificate

.DESCRIPTION
    Imports a certificate

.PARAMETER certPath
    Description: Certificate path

.PARAMETER certRootStore
    Description:    Certificate root store

.PARAMETER certStore
    Description:    Name of certificate for saving.

.EXAMPLE
    Invoke-OGImportCertificate

.NOTES
    Name:       Get-OGFileCertificate       
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2020-30-07
    Updated:    -
    
    Version history:
    1.0.0 - (2020-30-07) Function created
#>
function Invoke-OGImportCertificate (){
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$certPath,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$certRootStore,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$certStore
    )
    try {
        Write-OGLogEntry -LogText "Importing Ceritificate $($certPath)"
        $pfx = new-object System.Security.Cryptography.X509Certificates.X509Certificate2
        $pfx.import($certPath)
        $store = new-object System.Security.Cryptography.X509Certificates.X509Store($certStore, $certRootStore)
        $store.open("MaxAllowed")
        $store.add($pfx)
        $store.close()
        Write-OGLogEntry -LogText "Success importing Ceritificate $($certPath)"
        return $true
    }
    catch [System.Exception] {
        Write-OGLogEntry -LogText "Failed importing Ceritificate $($certPath). Error Message $($_.Exception.Message)" -logType Error
        return $false
    }
}

<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER certPath
Parameter description

.PARAMETER certRootStore
Parameter description

.PARAMETER certStore
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>
function Invoke-OGRemoveCertificate {
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$certPath,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$certRootStore,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$certStore
    )
    $CurrentCerts = get-childitem -Path "Cert:\LocalMachine\Root" | Select-Object -ExpandProperty "Thumbprint"
    $CertThumb = Get-PfxCertificate -Filepath $($certPath) | Select-Object -ExpandProperty "Thumbprint"
    If ($CurrentCerts.Contains("$($CertThumb)")) {
        Write-OGLogEntry -LogText "Found certificate $($certPath) with thumbprint already $($CertThumb) installed. Removing.."
        try {
            Remove-Item -Path "Cert:\$($certRootStore)\$($certStore)\$($CertThumb)" -Force
            Write-OGLogEntry -LogText "Success to removing certificate with Thumbprint: $($CertThumb)."
            return $true
        }
        catch [System.Excetion] {
            Write-OGLogEntry -LogText "Failed to remove certificate with Thumbprint: $($CertThumb). Error message: $($_.Exception.Message)" -LogType Error
            return $false
        }
    }
    Else {
        Write-OGLogEntry -LogText "Certificate $($Certificate.Name) not installed. Skipping." -logType Warning
        return $true
    }
}

<#
.SYNOPSIS
    Gets the drive with the most free space

.DESCRIPTION
    Gets the drive with the most free space available and returns it.

.EXAMPLE
    Get-OGDriveMostFree

.OUTPUTS
    Retruns the drive letter with the most avaialable space.

.NOTES
    Name:       Get-OGDriveMostFree       
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2020-30-07
    Updated:    -
    
    Version history:
    1.0.0 - (2020-30-07) Function created
#>
function Get-OGDriveMostFree {
    [cmdletbinding()]
    #Get Largest internal Drive
    $LogicalDrives = Get-WmiObject -Class Win32_logicaldisk -Filter "DriveType = '3'"
    $max = ($LogicalDrives | measure-object -Property FreeSpace -maximum).maximum
    $MostCapacityDrive = $LogicalDrives | Where-Object { $_.FreeSpace -eq $max }
    Write-OGLogEntry -logText "Success analysing drive capacity. $($MostCapacityDrive.DeviceID) has most amount of space free."
    $DMFS = "$($MostCapacityDrive.DeviceID)"
    return $DMFS
}

<#
.SYNOPSIS
    Search logical drives for path

.DESCRIPTION
    Gathers all logical drives on systema and searches for the path specified.
    Will then return the path if found.

.PARAMETER PathMinusDrive
    Description: path to search for

.EXAMPLE
    Start-OGSearchLogicalDrives -PathMinusDrive "VirtualMachines"
.Example
    Start-OGSearchLogicalDrives -PathMinusDrive "$ENV:Windir\Temp\file.txt"

.NOTES
    Name:       Start-OGSearchLogicalDrives   
	Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2020-06-08
    Updated:    -
    
    Version history:
    1.0.0 - (2020-06-08) Module created
#>
function Start-OGSearchLogicalDrives {        
    [cmdletbinding()] 
    param(
        [parameter(Mandatory = $true, HelpMessage = "My\Folder\Path") ]
        [ValidateNotNullOrEmpty()]
        [string]$PathMinusDrive
    )
    $LDA = New-Object System.Collections.Generic.List[System.Object]
    $Pathfound = $false
    $Count = 0
    $LogicalDrives = Get-WmiObject -Class Win32_logicaldisk -Filter "DriveType = '3'"
    foreach ($d in $LogicalDrives) {
        $LDA.Add($d)
    }
    do {
        Write-CMTLog -Value "Searching: '$($LDA[$Count].DeviceID)\$($PathMinusDrive)'"
        if (Test-Path "$($LDA[$Count].DeviceID)\$($PathMinusDrive)") {
            Write-CMTLog -Value "Found: '$($LDA[$Count].DeviceID)\$($PathMinusDrive)' returning."
            $Path = "$($LDA[$Count].DeviceID)\$($PathMinusDrive)"
            $PathFound = $true
        }
        $Count++
    } until (($PathFound -eq $true) -or ($Count -eq $LDA.Count))
    
    If ($PathFound) {
        return $Path
    }
    else {
        Write-OGLogEntry -logText "Could not find: '$($PathMinusDrive)' on any drives. Returning $false." -logType Warning
        return $false
    }
}

<#
.SYNOPSIS
    Converts file size.

.DESCRIPTION
    Converts file size.

.PARAMETER From
    Set: "Bytes", "KB", "MB", "GB", "TB"

.PARAMETER To
    Description: Convert it to
    Set: "Bytes", "KB", "MB", "GB", "TB"

.PARAMETER Value
    Description: The amount to convert.

.PARAMETER Precision
    Description: To N decimal places.

.EXAMPLE
    Converting 123456MB to GB:
        Convert-OGFileSize -From MB -To GB -Value 123456
    Result:
        120.5625

.NOTES
    Name:               Get-OGMSOfficeActiveProcesses 
    Original Source:    https://techibee.com/powershell/convert-from-any-to-any-bytes-kb-mb-gb-tb-using-powershell/237
    Updated by:         Richie Schuster - SCCMOG.com
    GitHub:             https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:            https://www.sccmog.com
    Contact:            @RichieJSY
    Created:            https://techibee.com/powershell/convert-from-any-to-any-bytes-kb-mb-gb-tb-using-powershell/237
    Updated:            2021-08-17

    Version history:
    1.0.0 - 2021-08-17 Function created
#>
function Convert-OGFileSize {            
    [cmdletbinding()]            
    param(            
        [validateset("Bytes", "KB", "MB", "GB", "TB")]            
        [string]$From,            
        [validateset("Bytes", "KB", "MB", "GB", "TB")]            
        [string]$To,            
        [Parameter(Mandatory = $true)]            
        [double]$Value,            
        [int]$Precision = 4            
    )            
    switch ($From) {            
        "Bytes" { $value = $Value }            
        "KB" { $value = $Value * 1024 }            
        "MB" { $value = $Value * 1024 * 1024 }            
        "GB" { $value = $Value * 1024 * 1024 * 1024 }            
        "TB" { $value = $Value * 1024 * 1024 * 1024 * 1024 }            
    }                     
    switch ($To) {            
        "Bytes" { return $value }            
        "KB" { $Value = $Value / 1KB }            
        "MB" { $Value = $Value / 1MB }            
        "GB" { $Value = $Value / 1GB }            
        "TB" { $Value = $Value / 1TB }                        
    }                      
    return [Math]::Round($value, $Precision, [MidPointRounding]::AwayFromZero)                     
}

<#
.SYNOPSIS
    Scan for files that are ouside the usual storage location - "Out Of Bounds"

.DESCRIPTION
    This function is designed to search for files "Out of Bounds" but can also be used to scan a machine
    and look for what is required.

.PARAMETER Search_Path
    Type: String Array
    Required: True
    Description: Path(s) to be searched
    Example: @("$($ENV:SystemDrive)",'D:\Temp')

.PARAMETER Exclude_Paths
    Description: Path(s) to be excluded

.PARAMETER FileTypes
    Description: File types to include. 

.PARAMETER MaxThreads
    Description: Max Job threads.

.EXAMPLE
    PS C:\> Get-OGOoBFiles -Search_Path $Paths -Exclude_Paths $Excludes -FileTypes $Include
    Running and assinging parameters.
    Setting Variables:
        [string[]]$Paths = @("$($ENV:SystemDrive)\")# 'D:\Temp')
        [string[]]$Excludes = @("$($ENV:SystemDrive)\Users", "$(${ENV:ProgramFiles(x86)})", "$($ENV:ProgramFiles)", "$($ENV:windir)")
        [string[]]$Include = @('*.txt', '*.pdf', '*.pst', '*.xlsx', '*.pptx', '*.pub', '*.docx', '*.csv','*.mp4')
    

.EXAMPLE   
    PS C:\> Get-OGOoBFiles -Search_Path $Paths -Exclude_Paths $Excludes -FileTypes $Include -MaxThreads 2
    Running and assinging parameters with max 2 Jobs.
    Varable Example:
        [string[]]$Paths = @("$($ENV:SystemDrive)\")# 'D:\Temp')
        [string[]]$Excludes = @("$($ENV:SystemDrive)\Users", "$(${ENV:ProgramFiles(x86)})", "$($ENV:ProgramFiles)", "$($ENV:windir)")
        [string[]]$Include = @('*.txt', '*.pdf', '*.pst', '*.xlsx', '*.pptx', '*.pub', '*.docx', '*.csv','*.mp4')
    
 


.NOTES
    Name:       Get-OGOoBFiles       
	Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-08-11
    Updated:    -
    
    Version history:
    1.0.0 - 2021-08-11 Function created
#>
function Get-OGOoBFiles {
    [cmdletbinding()]
    param(
        [string[]]$Search_Path = @("$($ENV:SystemDrive)\"),
        [string[]]$Exclude_Paths,
        [string[]]$FileTypes,
        [int]$MaxThreads = 10
    )
    #Create Generic Lists
    $Valid_Paths = New-Object System.Collections.Generic.List[System.Object]
    $Jobs = New-Object System.Collections.Generic.List[System.Object]
    $OOB_Files = New-Object System.Collections.Generic.List[System.Object]
    #Embedded function to process compplete jobs
    function processCompleteJobs {
        param(
            $List
        )
        $Complete_Jobs = Get-Job -State Completed
        foreach ( $job in $Complete_Jobs ) {
            $job_Data = Receive-Job $job 
            Remove-Job $job -Force
            $List.Add($job_Data)
        }
    }
    #Get all folders on root of drive
    $RootFolders = Get-ChildItem -Directory -Recurse -Depth 0 -Path $Search_Path
    #Exclude out path
    foreach ($folder in $RootFolders) {
        if (("$($folder.FullName)" -notin $Exclude_Paths) -and ("$($folder.FullName)\" -notin $Exclude_Paths)) {
            $Valid_Paths.Add($folder)
        }
    }
    $SearchPath_Block = {
        param(
            [string]$SearchPath,
            [string[]]$IncludeTypes
        )
        $files = $null
        $files = Get-ChildItem $SearchPath -Recurse -Include $IncludeTypes
        return $files
    }
    #Search locations found with seperate jobs to increase speed.
    $Count_Paths = 0
    foreach ($path in $Valid_Paths) {
        $Jobs += Start-Job -Name "Search: '$($path)'" -ScriptBlock $SearchPath_Block -ArgumentList ($path.FullName, $FileTypes)
        Write-Progress -Activity "Searching locations found..." -Status "Processing..." -PercentComplete ( $Count_Paths / $Valid_Paths.Count * 100 )
        ++$Count_Paths
        while ( ( Get-Job -State Running).count -ge $maxThreads ) { Start-Sleep -Seconds 3 }
        processCompleteJobs -List $OOB_Files
    }
    # process remaining jobs 
    Write-Progress -Activity "Completing search for locations found..." -Status "Processing..." -PercentComplete 100
    $Null = Get-Job | Wait-Job
    processCompleteJobs -List $OOB_Files

    if ($OOB_Files.Count -gt 0) {
        return $OOB_Files
    }
    else {
        return $false
    }
}

<#
.SYNOPSIS
    #Create Edge PWA Applications from URL

.DESCRIPTION
    This Function will create Edge PWA Applications from a JSON file. 

.PARAMETER ConfigFile
    Path to JSON Config File

.PARAMETER Icons
    Patch to Icon root folder

.EXAMPLE
    New-OGPWAApplications -Mode Install -ConfigFile "C:\Admin\New-CustomPWAApp\PWA_Applications.json" -Icons "C:\Admin\New-CustomPWAApp\icons"
.EXAMPLE
    New-OGPWAApplications -Mode Uninstall -ConfigFile "C:\Admin\New-CustomPWAApp\PWA_Applications.json"

.NOTES
    Name:       New-OGPWAApplications       
	Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-08-11
    Updated:    -
    
    Version history:
    1.0.0 - 2021-08-11 Function created
#>
function New-OGPWAApplications {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = 'Path to JSON ConfigFile')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Install", "Uninstall")]
        [String]$Mode,
        [Parameter(Mandatory = $true, HelpMessage = 'Path to JSON ConfigFile')]
        [String]$ConfigFile,
        [Parameter(Mandatory = $false, HelpMessage = 'Path to ICON Source')]
        [String]$Icons
    )
    if (Test-Path "$($ConfigFile)") {
        $Config = Get-Content  "$($ConfigFile)" | ConvertFrom-Json
        $Arguments = $null
        #$EdgePath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
        $EdgeProxyPath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge_proxy.exe"
        if (!(Test-Path $EdgeProxyPath)) {
            Write-CMTLog -Value "Edge Proxy not found at: $($EdgeProxyPath)"
            return $false
        }
        $ActiveUser = Get-LoggedOnUser -UniqueUserDomain INT 
        if ($ActiveUser) {
            $PWAIcons = "$($ENV:systemdrive)\users\$($ActiveUser.Username)\AppData\Roaming\PWAIcons"
            foreach ($item in $Config) {
                $Sr = "$($ENV:systemdrive)\users\$($ActiveUser.Username)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\"
                $Scp = Join-Path -Path $Sr -ChildPath "$($item.Application).lnk"
                switch ($ScriptMode) {
                    "Install" {
                        Write-OGLogEntry -logText "Creating PWA: '$($item.Application)' created for: '$($ActiveUser.Username)'"
                        try {
                            if (Test-Path "$($Icons)\$($item.icon)") {
                                if (!(Test-Path "$($PWAIcons)" -PathType Container)) {
                                    New-Item -Path "$($PWAIcons)" -ItemType Directory -Force | Out-Null
                                }
                                Copy-Item -Path "$($Icons)\$($item.icon)" -Destination "$($PWAIcons)\$($item.icon)" -Force
                            }
                            else {
                                Write-OGLogEntry -logText "Failed during shortcut icon copy for icon: $($item.icon). Error: '$($Icons)\$($item.icon)' not found!" -logType Error
                                return $false
                            }
                            
                        }
                        catch [System.Exception] {
                            Write-OGLogEntry -logText "Failed during shortcut icon copy for icon: $($item.icon). Error: $($_.Exception.Message)" -logType Error
                            return $false
                        }
                        try {
                            # Create Start Menu Shortcut
                            [string]$Arguments = "--profile-directory=`"$($item.Application)`" --app=`"$($item.Link)`" --no-first-run --no-default-browser-check "
                            $ws = New-Object -com WScript.Shell
                            $Sc = $ws.CreateShortcut($Scp)
                            $Sc.TargetPath = $EdgeProxyPath
                            $Sc.IconLocation = "$($PWAIcons)\$($item.icon)" 
                            $sc.Arguments = $Arguments
                            $Sc.Description = $($item.Application)
                            $Sc.Save()
                        }
                        catch [System.Exception] {
                            Write-OGLogEntry -logText "Failed during shortcut creation.  Error: $($_.Exception.Message)" -logType Error
                            return $false
                        }
                        Write-OGLogEntry -logText "PWA: '$($item.Application)' created for: '$($ActiveUser.Username)' at: '$($Scp)'"
                        return $true    
                    }
                    "Uninstall" {
                        try {
                            if (Test-Path "$($Scp)") {
                                Remove-Item -Path "$($Scp)" -Force
                                return $true
                            }
                            else {
                                Write-OGLogEntry -logText "Shortcut not found at: '$($Scp)' no need to clean."
                                return $true
                            }
                            if (Test-Path "$($PWAIcons)\$($item.icon)") {
                                Remove-Item -Path "$($PWAIcons)\$($item.icon)" -Force
                                return $true
                            }
                            else {
                                Write-OGLogEntry -logText "Shortcut icon not found for icon: '$($item.icon)' not found at: '$($PWAIcons)\$($item.icon)' no need to clean."
                                return $true
                            }
                        }
                        catch [System.Exception] {
                            Write-OGLogEntry -logText "Failed during shortcut removal. Error: $($_.Exception.Message)" -logType Error
                            return $false
                        }
                    }
                }

            }
        }
        else {
            Write-OGLogEntry -logText "No active user on: $($ENV:ComputerName) bailing out..."
            return $false
        }
    }
    else {
        Write-OGLogEntry -logText "No config file found at: $($ConfigFile) bailing out..."
        return $false
    }
}

<#
.SYNOPSIS
Create a new Shortcut

.DESCRIPTION
This function has been designed to create a shortcut.

.PARAMETER Target
The target of the shortcut:
            
.PARAMETER TargetArgs
Arguments of the shortcut

.PARAMETER RunAsAdmin
If specified will force the shortcut to run as Admin

.PARAMETER ShortcutName
Shortcut filename

.PARAMETER ShortcutLocation
Shortcut location

.PARAMETER ShortcutType
Shortcut to file or URL. 
File type set to:
    File - .lnk
    URL  - .url 

.EXAMPLE
    New-OGShortcut -Target "$ENV:windir\System32\vmconnect.exe" -TargetArgs "localhost VMNameHere" -RunAsAdmin -ShortcutName "RichiesVM" -ShortcutLocation "$env:Public\Desktop" -ShortcutType "File"
    Creates a shortcut.

.NOTES
    Name:       New-OGShortcut       
	Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2020-30-07
    Updated:    -
    
    Version history:
    1.0.0 - (2020-30-07) Function created
#>
function New-OGShortcut {
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Target,
        [parameter(Mandatory = $false)]
        [string]$TargetArgs,
        [parameter(Mandatory = $false)]
        [switch]$RunAsAdmin,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ShortcutName,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ShortcutLocation,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("File", "URL")]
        [string]$ShortcutType
    )
    switch ($ShortcutType) {
        "File" { 
            $FileType = "lnk" 
        }
        "URL" { 
            $FileType = "url" 
        }
    }
    $WScriptShell = New-Object -ComObject WScript.Shell
    $FinalShortcutLocation = "$($ShortcutLocation)\$($ShortcutName).$($FileType)"
    $Shortcut = $WScriptShell.CreateShortcut($FinalShortcutLocation)
    $Shortcut.TargetPath = $Target
    $Shortcut.Arguments = $TargetArgs
    $Shortcut.Save()
    if ($RunAsAdmin) {
        $bytes = [System.IO.File]::ReadAllBytes("$($FinalShortcutLocation)")
        $bytes[0x15] = $bytes[0x15] -bor 0x20 #set byte 21 (0x15) bit 6 (0x20) ON
        [System.IO.File]::WriteAllBytes("$($FinalShortcutLocation)", $bytes)
    }
}
##################################################################################################################################
# END Files/Folder Region
##################################################################################################################################
##################################################################################################################################
##################################################################################################################################
# Process Region
##################################################################################################################################

<#
.SYNOPSIS
Wait for a process to close

.DESCRIPTION
This function waits for a process to close. IF the process is not found at runtime it will consider it closed and report so.

.PARAMETER Process
Name of process to wait for.

.PARAMETER MaxWaitTime
How long to wait for the process. Default is 60 seconds.

.EXAMPLE
Wait-OGProcessClose -Process Notepad
Wait for the process Notepad to close with a default MaxWaitTime of 60s

.EXAMPLE
Wait-OGProcessClose -Process Notepad -MaxWaitTime 10
Wait for the process Notepad to close with a MaxWaitTime of 10s

.NOTES
    Name:       Wait-OGProcessClose       
	Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-09-21
    Updated:    -
    
    Version history:
    1.0.0 - 2021-09-21 Function created
#>
function Wait-OGProcessClose {
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Process,
        [parameter(Mandatory = $false)]
        [int]$MaxWaitTime = 60
    )
    $count = 0
    Do {
        $status = Get-Process | Where-Object { $_.Name -like "$process" }
        If ($status) {
            Write-OGLogEntry "Waiting for process: '$($Process)' with PID: $($status.id) to close." ; 
            $closed = $false
            Start-Sleep -Seconds 1
            $count++
        }        
        Else { 
            $closed = $true 
        }
    }
    Until (( $closed ) -or ( $count -eq $maxRetry ))
    if (($closed)-and($count -eq 0)){
        Write-OGLogEntry "Process: '$($Process)' was not found to be running."
        return $true
    }
    elseif (($closed)-and($count -gt 0)){
        Write-OGLogEntry "Process: '$($Process)' has closed."
        return $true
    }
    else{
        Write-OGLogEntry "MaxWaitTime: $($MaxWaitTime) reached waiting for process: '$($Process)' with PID: $($status.id) to close." ;
        return $false
    }
}

<#
.SYNOPSIS
Wait for a process to start

.DESCRIPTION
This function waits for a process to start. IF the process is found at runtime it will consider it started and report so.

.PARAMETER Process
Name of process to wait for.

.PARAMETER MaxWaitTime
How long to wait for the process. Default is 60 seconds.

.EXAMPLE
Wait-OGProcessStart -Process Notepad
Wait for the process Notepad to start with a default MaxWaitTime of 60s

.EXAMPLE
Wait-OGProcessStart -Process Notepad -MaxWaitTime 10
Wait for the process Notepad to start with a MaxWaitTime of 10s

.NOTES
    Name:       Wait-OGProcessStart       
	Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-09-21
    Updated:    -
    
    Version history:
    1.0.0 - 2021-09-21 Function created
#>
function Wait-OGProcessStart {
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Process,
        [parameter(Mandatory = $false)]
        [int]$MaxWaitTime = 60
        )
    $count = 0
    Do {
        $status = Get-Process | Where-Object { $_.Name -like "$process" }
        If (!($status)) {
            Write-OGLogEntry "Waiting for process: $($Process) to start." ; 
            $started = $false
            Start-Sleep -Seconds 1
            $count++
        }        
        Else { 
            $started = $true 
        }
    }
    Until (( $started ) -or ( $count -eq $maxRetry ))
    if (($started)-and($count -eq 0)){
        Write-OGLogEntry "Process: '$($Process)' with PID: $($status.id) was found to be already running."
        return $true
    }
    elseif (($started)-and($count -gt 0)){
        Write-OGLogEntry "Process: '$($Process)' with PID: $($status.id) has started."
        return $true
    }
    else{
        Write-OGLogEntry "MaxWaitTime: $($MaxWaitTime) reached waiting for process: $($Process) to start." ;
        return $false
    }
}
##################################################################################################################################
# END Process Region
##################################################################################################################################
##################################################################################################################################
##################################################################################################################################
#  Scheduled Task Region
##################################################################################################################################

<#
.SYNOPSIS
    Gets A Windows 7/Server 2008 Sceduled Task. 

.DESCRIPTION
    Gets A Windows 7/Server 2008 Sceduled Task. 

.PARAMETER TaskName
    Name of task to search for.

.EXAMPLE
    Get-OGWin7ScheduledTask -TaskName "My Task Name here"

.NOTES
    Name:       2021-08-17       
	Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    
    Updated:    -
    
    Version history:
    1.0.0 - 2021-08-17 Script created
#>
Function Get-OGWin7ScheduledTask {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = 'Name of Task to search for.')]
        [ValidateNotNullOrEmpty()]
        [String]$TaskName
    )
    $Schedule = New-Object -ComObject "Schedule.Service"
    $Schedule.Connect('localhost')
    $Folder = $Schedule.GetFolder('\')
    $Folder.GetTask($TaskName)
}

<#
.SYNOPSIS
    Stops a scheduled task
.DESCRIPTION
    Stops a scheduled task

.PARAMETER TaskName
    Name of task to stop.

.EXAMPLE
    Stop-OGScheduledTask -TaskName "Name Of My Task"

.NOTES
    Name:       Stop-OGScheduledTask       
	Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-08-17
    Updated:    -
    
    Version history:
    1.0.0 - 2021-08-17 Script created
#>
Function Stop-OGScheduledTask {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = 'Name of Scheduled Task to stop')]
        [ValidateNotNullOrEmpty()]
        [String]$TaskName
    )
    $OSVersion = Get-OSVersionNT
    $error.Clear()
    if ($OSVersion -gt 601) {
        Get-ScheduledTask $TaskName | Stop-ScheduledTask
        return $true
    }
    else {
        SCHTASKS /end /TN $TaskName
        return $true
    }
    if ($Error) {
        Write-OGLogEntry -logText "Failed to stop ($TaskName). Error: $($Error[0].Exception.Message)" -logtype Error
    }
}

<#
.SYNOPSIS
    Starts a scheduled task.

.DESCRIPTION
    Starts a scheduled task.

.PARAMETER TaskName
    Name of task to stop.

.EXAMPLE
    Start-OGScheduledTask -TaskName "Your Task Name"

.NOTES
    Name:       Start-OGScheduledTask       
	Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-08-17
    Updated:    -
    
    Version history:
    1.0.0 - 2021-08-17 Script created
#>
Function Start-OGScheduledTask {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = 'Name of Scheduled Task to Start')]
        [ValidateNotNullOrEmpty()]
        [String]$TaskName
    )
    $error.Clear()
    $OSVersion  #= Get-OSVersionNT
    if ($OSVersion -gt 601) {
        Start-ScheduledTask $TaskName
        Write-OGLogEntry -logText "Starting $TaskName ($OSVersion )."

    }
    else {
        SCHTASKS.EXE /RUN /TN "$TaskName"
        Write-OGLogEntry -logText "Started $TaskName ($OSVersion)."
    }
    if ($Error) {
        Write-OGLogEntry -logText "Failed to start $taskname ($OSVersion). Error: $($Error[0].Exception.Message)" -logtype Error
    }
}

<#
.SYNOPSIS
    Removes a registered scheduled task

.DESCRIPTION
    Removes a registered scheduled task

.PARAMETER TaskName
    Name of task to remove.

.EXAMPLE
    Remove-OGScheduledTask -TaskName "Your Task Name"

.NOTES
    Name:       Remove-OGScheduledTask       
	Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-08-17
    Updated:    -
    
    Version history:
    1.0.0 - 2021-08-17 Script created
#>
Function Remove-OGScheduledTask {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = 'Name of Scheduled Task to Start')]
        [ValidateNotNullOrEmpty()]
        [String]$TaskName
    )
    if ($OSVersion -gt 601) {
        Unregister-ScheduledTask -TaskName "$($TaskName)" -Confirm:$false
        Start-Sleep -Seconds 1

        if ($Error) {
            Write-OGLogEntry -logText "Failed to clear scheduled tasks. Error: $($Error.Exception.Message)" -logtype Error
        }
        else {
            Write-OGLogEntry -logText "Success removing registered task: '$($TaskName)'"
            return $true
        }
    
    }
    else {
        schtasks /delete /tn "$($TaskName)" /F
        if ($Error) {
            Write-OGLogEntry -logText "Failed removing scheduled tasks (win7/2008). Error: $($Error[0].Exception.Message)" -logtype error
        }
        else {
            Write-OGLogEntry -logText "Success removing registered task: '$($TaskName)'"
        }
    }
}
##################################################################################################################################
# End Scheduled Task Region
##################################################################################################################################
##################################################################################################################################
##################################################################################################################################
# Script Region
##################################################################################################################################

<#
.SYNOPSIS
    Starts a script sleep with progress.

.DESCRIPTION
    This function starts a sleep command with a GUI and CLI progress bar.

.PARAMETER seconds
    Specifies how long to sleep for. 

.EXAMPLE
    Start-OGSleeper -Seconds 20

.NOTES
    Name:       Start-OGSleeper   
	Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2020-30-07
    Updated:    -
    
    Version history:
    1.0.0 - (2020-30-07) Module created
#>
function Start-OGSleeper ($seconds) {
    [cmdletbinding()]
    $doneDT = (Get-Date).AddSeconds($seconds)
    Write-OGLogEntry -logText "Sleeping for $($seconds) seconds:"
    while ($doneDT -gt (Get-Date)) {
        $secondsLeft = $doneDT.Subtract((Get-Date)).TotalSeconds
        $SecondsCount
        $percent = ($seconds - $secondsLeft) / $seconds * 100
        Write-Progress -Activity "Sleeping" -Status "Sleeping..." -SecondsRemaining $secondsLeft -PercentComplete $percent
        Write-OGLogEntry -logText -Value -NoNewline "."
        [System.Threading.Thread]::Sleep(500)
    }
    Write-Progress -Activity "Sleeping" -Status "Sleeping..." -SecondsRemaining 0 -Completed
    Write-OGLogEntry -logText "Complete"
}

<#
.SYNOPSIS
    Get and report on all script variables.

.DESCRIPTION
    Get and report on all script variables.

.EXAMPLE
    Get-OGUDVariables

.NOTES
    Name:       Get-OGUDVariables       
	Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-08-17
    Updated:    -
    
    Version history:
    1.0.0 - 2021-08-17 Script created
#>
function Get-OGUDVariables {
    if ($PSVersionTable.PSVersion.Major -gt 2) {
        Write-OGLogEntry -logText "Powershell Version: $($PSVersionTable.PSVersion.Major)"
        Write-OGLogEntry -logText "Custom Script Variables:"
        Write-OGLogEntry -logText "============================"
        $Variables = get-variable | where-object { (@(
                    "FormatEnumerationLimit",
                    "MaximumAliasCount",
                    "MaximumDriveCount",
                    "MaximumErrorCount",
                    "MaximumFunctionCount",
                    "MaximumVariableCount",
                    "PGHome",
                    "PGSE",
                    "PGUICulture",
                    "PGVersionTable",
                    "PROFILE",
                    "PSSessionOption"
                ) -notcontains $_.name) -and `
            (([psobject].Assembly.GetType('System.Management.Automation.SpecialVariables').GetFields('NonPublic,Static') |`
                        Where-Object FieldType -eq ([string]) | ForEach-Object GetValue $null)) -notcontains $_.name
        }
        Write-OGLogEntry -logText "[Name]`t`t[Value]"
        $Variables | ForEach-Object { Write-OGLogEntry -logText "$($_.Name):`t`t$($_.Value)" }
        Write-OGLogEntry -logText  "============================"
    }
    else {
        Write-OGLogEntry -logText  "Powershell Version: $($PSVersionTable.PSVersion.Major) Unable to list Custom Script Variables." -logType Warning
    }
}
##################################################################################################################################
# Script Region
##################################################################################################################################
##################################################################################################################################
##################################################################################################################################
# Service Region
##################################################################################################################################
<#
.SYNOPSIS
    Checks if a Windows Service exists

.DESCRIPTION
    Checks if a Windows Service exists

.PARAMETER ServiceName
    Description:    Name of servie to test for.

.EXAMPLE
    Test-OGServiceExists -ServiceName XboxGipSvc

.NOTES
    Sourced:    #https://stackoverflow.com/questions/4967496/check-if-a-windows-service-exists-and-delete-in-powershell    
    Name:       Test-OGServiceExists   
	Updated:    Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2020-30-07
    Updated:    -
    
    Version history:
    1.0.0 - (2020-30-07) Module created

#>
Function Test-OGServiceExists{
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ServiceName
    )
    [bool] $Return = $False
    if ( Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" ) {
        $Return = $True
    }
    Return $Return
}

<#
.SYNOPSIS
    Checks if a Windows Service exists

.DESCRIPTION
    Checks if a Windows Service exists

.PARAMETER ServiceName
    Description:    Name of servie to test for.

.EXAMPLE
    Remove-OGService -ServiceName XboxGipSvc

.NOTES
    Sourced:    https://stackoverflow.com/questions/4967496/check-if-a-windows-service-exists-and-delete-in-powershell  
    Name:       Remove-OGService   
	Updated:    Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2020-30-07
    Updated:    -
    
    Version history:
    1.0.0 - (2020-30-07) Module created

#>
Function Remove-OGService () {
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ServiceName
    )
    $Service = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" 
    if ($Service) {
        $Service.Delete()
        if (!( Test-OGServiceExists -ServiceName $ServiceName)) {
            return $true
        }
        else{
            return $false
        }
    }
    Else{
        Write-OGLogEntry -logText "No service with name: $($ServiceName)" -LogType Warning
        return $false
    }
}
##################################################################################################################################
# End Service Region
##################################################################################################################################

#Get-ChildItem function: | Where-Object { ($currentFunctions -notcontains $_)-and($_.Name -like "*-OG*") } | Select-Object -ExpandProperty name
$Export = @(
    "Convert-OGFileSize",
    "Get-OGDriveMostFree",
    "Get-OGFileCertificate",
    "Get-OGMSOfficeActiveProcesses",
    "Get-OGOoBFiles",
    "Get-OGOSVersionNT",
    "Get-OGTempStorage",
    "Get-OGUDVariables",
    "Get-OGWin7ScheduledTask",
    "Invoke-OGImportCertificate",
    "Invoke-OGRemoveCertificate",
    "New-OGPWAApplications",
    "New-OGShortcut",
    "Remove-OGScheduledTask",
    "Remove-OGService",
    "Start-OGScheduledTask",
    "Start-OGSearchLogicalDrives",
    "Start-OGSleeper",
    "Stop-OGScheduledTask",
    "Test-OGServiceExists",
    "Wait-OGProcessClose",
    "Wait-OGProcessStart"
)

foreach ($module in $Export){
    Export-ModuleMember $module
}
