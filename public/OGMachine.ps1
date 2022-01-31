##################################################################################################################################
#  Process Region
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
    Write-OGLogEntry "Getting active MS Office Proccesses."
    $ActiveProcesses = Get-Process | Where-Object { (($_.path -like "*\Microsoft Office\*")`
                -or ($_.ProcessName -like "*lync*")`
                -or ($_.ProcessName -like "*Outlook*")`
                -or ($_.ProcessName -like "*OneNote*")`
                -or ($_.ProcessName -like "*Groove*")`
                -or ($_.ProcessName -like "*MSOSync*")`
                -or ($_.ProcessName -like "*Teams*")`
                -or ($_.ProcessName -like "*EXCEL*")`
                -or ($_.ProcessName -like "*WINWORD*")`
                -or ($_.ProcessName -like "*POWERPNT*")`
                -or ($_.ProcessName -like "*MSACCESS*")`
                -or ($_.ProcessName -like "*MSPUB*")`
                -or ($_.ProcessName -like "*OneDrive*")`
                -or ($_.ProcessName -like "*CompanyPortal*"))  }
    if ($ActiveProcesses){
        Write-OGlogentry "Found active MS Office Proccesses [Process: $(($activeO365Apps.ProcessName)-join "][Process: ")]" -logtype Warning
        Return $ActiveProcesses
    }
    else{
        Write-OGlogentry "No active MS Office Proccesses found."
        return $false
    }
}

<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER commandTitle
Parameter description

.PARAMETER commandPath
Parameter description

.PARAMETER commandArguments
Parameter description

.EXAMPLE
An example

.NOTES
    Name:       Get-OGMSOfficeActiveProcesses
    Original:   https://stackoverflow.com/questions/8761888/capturing-standard-out-and-error-with-start-process
    Updated:    Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-08-17
    Updated:    -

    Version history:
        1.0.0 - 2021-08-17 Function created
# 
#>    
Function Start-OGCommand (){
    [cmdletbinding()]
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Arguments,
        [parameter(Mandatory = $False)]
        [ValidateNotNullOrEmpty()]
        [string]$Title = "Execute Command",
        [parameter(Mandatory = $False)]
        [switch]$Wait = $false
    )
    Write-OGLogEntry "Executing [$($Title): '$($Path) $($Arguments)'] [Wait: $($Wait)]"
    try{
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = $Path
        $pinfo.RedirectStandardError = $true
        $pinfo.RedirectStandardOutput = $true
        $pinfo.UseShellExecute = $false
        $pinfo.Arguments = $Arguments
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $pinfo
        $p.Start() | Out-Null
        if ($Wait){
            $p.WaitForExit()
        }
        $OutPut = [pscustomobject]@{
            commandTitle = $Title
            stdout = $p.StandardOutput.ReadToEnd()
            stderr = $p.StandardError.ReadToEnd()
            ExitCode = $p.ExitCode  
        }
        Write-OGLogEntry "Success Executing [$($Title): '$($Path) $($Arguments)'] [Wait: $($Wait)] [Exit Code: $($OutPut.ExitCode)]"
        return $OutPut
    }
    catch{
        Write-OGLogEntry "FAILED Executing [$($Title): '$($Path) $($Arguments)'] [Wait: $($Wait)]" -logType Error
    }
}


##################################################################################################################################
# End Process Region
##################################################################################################################################
##################################################################################################################################
##################################################################################################################################
# Files Folder Region
##################################################################################################################################

<#
.SYNOPSIS
Search for a directory

.DESCRIPTION
Search for a directory and if found return the details about it.

.PARAMETER Path
Where to search

.PARAMETER Name
Name of the folder to search for

.PARAMETER Recurse
Should the function search in recurse mode

.EXAMPLE
Get-OGFolderLocation -Path "$($env:ProgramFiles)","$(${env:ProgramFiles(x86)})" -Name "*Richie*"

.EXAMPLE
Get-OGFolderLocation -Path "$($env:ProgramFiles)","$(${env:ProgramFiles(x86)})" -Name "*Richie*" -Recurse

.NOTES
    Name:       Get-OGFolderLocation
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-12-09
    Updated:    -

    Version history:
        1.0.0 - 2021-12-09 Function created
#>
function Get-OGFolderLocation (){
    [cmdletbinding()]
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [parameter(Mandatory = $false)]
        [switch]$Recurse
    )
    Write-OGLogEntry "Searching for [Folder: $($Name)] at [Path: $($Path)] [Recurse: $Recurse]"
    $Found = @()
    if (!($Recurse)){
        $DirFound = Get-ChildItem $Path -Filter "*$($Name)*" -directory -ErrorAction SilentlyContinue
    }
    else{
        $DirFound = Get-ChildItem $Path -Filter "*$($Name)*" -directory -Recurse -ErrorAction SilentlyContinue
    }
    foreach ($dir in $DirFound){
        $objDir = $null
        $objDir = [PSCustomObject]@{
            Name = $dir.Name
            FullName = $dir.FullName
            Parent = $dir.Parent
            Root = $dir.Root
            CreationTime = $dir.CreationTime
            LastAccessTime = $dir.LastAccessTime
            LastWriteTime = $dir.LastWriteTime
        }
        $Found += $objDir
    }
    if ($found){
        Write-OGLogEntry "Found [Folder: $($Name)] at [Path(s): '$($Found.FullName -join "' | '")'] [Recurse: $Recurse]"
        return $Found
    }
    else{
        Write-OGLogEntry "Did not find [Folder: $($Name)] at [Path(s): '$($Path -join "' | '")'] [Recurse: $Recurse]"
        return $null
    }
}


<#
.SYNOPSIS
Find a file

.DESCRIPTION
This function will find a file in a directory and return it if found.
You can also specify every location a file with same name is found to be returned.

.PARAMETER Path
Path(s) to search

.PARAMETER Name
Name of file to look for.

.PARAMETER All
Should the function return all available locations the file was found or not.

.EXAMPLE
Get-OGFileLocation -Path $env:ProgramFiles -Name FindMe.txt
Find the first location only

.EXAMPLE
Get-OGFileLocation -Path $env:ProgramFiles,$ENV:ProgramData -Name FindMe.txt -All
Finds all the locations

.NOTES
    Name:       Get-OGFileLocation
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-12-09
    Updated:    -

    Version history:
        1.0.0 - 2021-12-09 Function created
#>
function Get-OGFileLocation (){
    [cmdletbinding()]
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [parameter(Mandatory = $false)]
        [switch]$All
    )
    Write-OGLogEntry "Searching for [File: $($Name)] at [Path: '$($Path -join "' | '")'] [All Locations: $All]"
    $Found = @()
    foreach($dir in $Path){
        $FileFound = Get-ChildItem -Path "$($dir)" -Filter "$($Name)" -Recurse -ErrorAction SilentlyContinue
        If ($FileFound){
            $FileDetails = $null
            $objFile = $null
            $FileDetails = Get-Item $FileFound.FullName
            $objFile = [PSCustomObject]@{
                Name = $FileDetails.Name
                FullName = $FileDetails.FullName
                Directory = $FileDetails.Directory
                Size = $FileDetails.Length
                Extension = $FileDetails.Extension
                CreationTime = $FileDetails.CreationTime
                LastAccessTime = $FileDetails.LastAccessTime
                LastWriteTime = $FileDetails.LastWriteTime
            }
            if (!$All){
                Write-OGLogEntry "Found [File: $($Name)] at [Path: $($objFile.Directory)] [All Locations: $All]"
                return $objFile
            }
            else{
                $Found += $objFile
            }
        }
    }
    if ($Found){
        Write-OGLogEntry "Found [File: $($Name)] at [Path(s): '$($Found.Directory -join "' | '")'] [All Locations: $All]"
        return $Found
    }
    else{
        Write-OGLogEntry "Did not find [File: $($Name)] at [Path(s): '$($Path -join "' | '")'] [All Locations: $All]"
        return $null
    }
}

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
            $job_Data = $Null
            $job_Data = Receive-Job $job 
            Remove-Job $job -Force
            if ($job_Data){
                $List.Add($job_Data)
            }
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
    Updated:    2021-11-24
    
    Version history:
    1.0.0 - 2021-08-11 Function created
    1.1.0 - 2021-11-24 Modified to use SCCMOG Module Functions
    1.1.1 - 2021-11-25 Changed to Get-OGLoggedOnUserWMI
#>
function New-OGPWAApplications{
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
    #$Mode = "Install"
    #$ConfigFile = "$($scriptRoot)\PWA_Applications.json"
    #$Icons = "$($scriptRoot)\icons"
    if (Test-OGFilePath "$($ConfigFile)") {
        $Config = Get-Content  "$($ConfigFile)" | ConvertFrom-Json
        $Arguments = $null
        $EdgeProxyPath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge_proxy.exe"
        if (!(Test-Path $EdgeProxyPath)) {
            Write-OGLogEntry "Edge Proxy not found at: $($EdgeProxyPath)"
            return $false
        }
        $ActiveUser = Get-OGLoggedOnUserCombined
        if ($ActiveUser) {
            $PWAIcons = "$($ActiveUser.APPDATA)\PWAIcons"
            foreach ($item in $Config) {
                $Sr = "$($ActiveUser.APPDATA)\Microsoft\Windows\Start Menu\Programs\"
                $Scp = Join-Path -Path $Sr -ChildPath "$($item.Application).lnk"
                switch ($Mode) {
                    "Install" {
                        Write-OGLogEntry -logText "Creating PWA: '$($item.Application)' for: '$($ActiveUser.Username)'"
                        try {
                            if (Test-OGFilePath "$($Icons)\$($item.icon)") {
                                if (!(Test-OGContainerPath "$($PWAIcons)")) {
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
                            [string]$Arguments = "--profile-directory=`"$($item.ProfileDir)`" --app=`"$($item.Link)`" --no-first-run --no-default-browser-check "
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
                    }
                    "Uninstall" {
                        try {
                            if (Test-OGFilePath "$($Scp)") {
                                Remove-Item -Path "$($Scp)" -Force
                            }
                            else {
                                Write-OGLogEntry -logText "Shortcut not found at: '$($Scp)' no need to clean."
                            }
                            if (Test-OGFilePath "$($PWAIcons)\$($item.icon)") {
                                Remove-Item -Path "$($PWAIcons)\$($item.icon)" -Force
                            }
                            else {
                                Write-OGLogEntry -logText "Shortcut icon not found for icon: '$($item.icon)' not found at: '$($PWAIcons)\$($item.icon)' no need to clean."
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

<#
.SYNOPSIS
Creates a new Microsoft Edge Profile for the current active user.

.DESCRIPTION
Creates a new Microsoft Edge Profile for the current active user and adds a shortcut to it in their Start Menu.

.PARAMETER Mode
Install or uninstall the new edge profile

.PARAMETER ProfileName
Name of the Profile to create

.EXAMPLE
New-OGMSEdgeProfile -Mode Install -ProfileName "Clarivate"

.EXAMPLE
New-OGMSEdgeProfile -Mode Unintall -ProfileName "Clarivate"

.NOTES
    Name:       New-OGMSEdgeProfile       
	Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-11-24
    Updated:    
    
    Version history:
    1.0.0 - 2021-11-24 Function created
    1.1.0 - 2021-11-25 Changed to Get-OGLoggedOnUserWMI
#>
function New-OGMSEdgeProfile{
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = 'Function Mode')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Install", "Uninstall")]
        [String]$Mode,
        [Parameter(Mandatory = $false, HelpMessage = 'Name of Profile to create.')]
        [String]$ProfileName = "Clarivate"
    )
    #Variables
    $MSEdge_ProfilePath = "profile-$($ProfileName)"
    $MSEdge_SCName = "Microsoft Edge - $($ProfileName)"
    $MSEdge_SCArgs = "--profile-directory=$MSEdge_ProfilePath --no-first-run --no-default-browser-check"
    $MSEdge_Exe = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    $LoggedonUser = Get-OGLoggedOnUserCombined
    if ($LoggedonUser){
        $MSEdge_SCLocation = "$($LoggedonUser.APPDATA)\Microsoft\Windows\Start Menu\Programs"
    }
    else{
        $message = "No user actively logged on. Bailing out."
        Write-OGLogEntry $message -logtype Error
        throw $message
    }
    switch ($Mode){
        "Install"{
            if (Test-OGFilePath -Path $MSEdge_Exe){
                New-OGShortcut -Target "$($MSEdge_Exe)" -TargetArgs "$MSEdge_SCArgs" -ShortcutName "$MSEdge_SCName" -ShortcutLocation "$MSEdge_SCLocation" -ShortcutType File
            }
            Else{
                $message = "Microsft Edge not installed on this machine. Bailing out."
                Write-OGLogEntry $message -logtype Error
                throw $message
            }   
        }
        "Uninstall"{
            if (Test-OGFilePath -Path "$($MSEdge_SCLocation)\$($MSEdge_SCName).lnk"){
                Remove-Item -Path "$($MSEdge_SCLocation)\$($MSEdge_SCName).lnk" -Force
            }
            Else{
                Write-OGLogEntry "Did not find [Shorcut: '$($MSEdge_SCLocation)\$($MSEdge_SCName).lnk'] no need to remove." -logtype Warning
            }   
        }
    }
 
}

<#
.SYNOPSIS
Exports Get-Childitem to an organsised object.

.DESCRIPTION
Exports Get-Childitem to an organsised object.

.PARAMETER Files
Results of Get-Childitem

.EXAMPLE
Export-OGFileDetails -Files $GetChildItemResult

.NOTES
    Name:       Export-OGFileDetails 
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-01-07
    Updated:    -

    Version history:
    1.0.0 - 2022-01-07 Function created
#>
function Export-OGFileDetails {
    param(
        [parameter(Mandatory = $true)]
        [object]$Files
    )
        Write-OGLogEntry "Begining file data organisation"
        $List = New-Object System.Collections.Generic.List[System.Object]
        try{
            foreach ($rootDir in $Files) {
                if ($rootDir -notlike $null) {
                    foreach ($file in $rootDir) {
                        $List.Add([PSCustomObject]@{
                                Name          = $file.Name
                                FullName      = $file.FullName
                                Directory     = $file.Directory
                                Size          = $file.Length
                                CreationTime  = $file.CreationTime
                                LastWriteTime = $file.LastWriteTime 
                            })
                    }
                }
            }
            Write-OGLogEntry "Fiile data organisation complete returning object."
            return $($List)
        }
        catch{
            $message = "Failed during data organisation. Error: $_"
            Write-OGLogEntry $message -logtype error
            throw $message
        } 
}


<#
.SYNOPSIS
Exports Get-Childitem result to CSV

.DESCRIPTION
Exports Get-Childitem result to CSV

.PARAMETER Files
Results of Get-Childitem

.PARAMETER ExportName
Name of csv to export

.PARAMETER ExportPath
Location to export CSV

.EXAMPLE
Export-OGFileDetailstoCSV -Files $GetChildItemResult -ExportName "MyCSV" -ExportPath "c:|my\folder\forcsvs"

.NOTES
    Name:       Export-OGFileDetailstoCSV 
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-10-27
    Updated:    -

    Version history:
    1.0.0 - 2021-10-27 Function created
#>
function Export-OGFileDetailstoCSV {
    param(
        [parameter(Mandatory = $true)]
        [object]$Files,
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ExportName,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExportPath
    )
    if (Test-OGContainerPath -Path $ExportPath){
        $List = New-Object System.Collections.Generic.List[System.Object]
        foreach ($rootDir in $Files) {
            if ($rootDir -notlike $null) {
                foreach ($file in $rootDir) {
                    $List.Add([PSCustomObject]@{
                            Name          = $file.Name
                            FullName      = $file.FullName
                            Directory     = $file.Directory
                            Size          = $file.Length
                            CreationTime  = $file.CreationTime
                            LastWriteTime = $file.LastWriteTime 
                        })
                }
            }
        }
        try{
            $CompletePath = "$($ExportPath)\$($ExportName).csv"
            Write-OGLogEntry "Attempting to export data to CSV: '$($CompletePath)'"
            $List | Export-Csv "$($CompletePath)" -NoClobber -NoTypeInformation -Force
            Write-OGLogEntry "Success exporting data to CSV: '$($CompletePath)'"
            $objExportDetails = ([PSCustomObject]@{
                Path          = $CompletePath
                TotalFiles    = $List.Count
            })
            return $($objExportDetails)
        }
        catch{
            $message = "Failed exporting data to CSV: '$($CompletePath)'. Error: $_"
            Write-OGLogEntry $message -logtype error
            throw $message
        } 
    }
    else{
        $message = "Path $($ExportPath) is not valid path."
        Write-OGLogEntry $message -logtype error
        throw $message
    } 
}

<#
.SYNOPSIS
Check for container/directory

.DESCRIPTION
Check for container/directory

.PARAMETER Path
Path to container/directory

.EXAMPLE
Test-OGContainerPath -Path C:\admin

.NOTES
    Name:       Test-OGContainerPath 
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-10-27
    Updated:    -

    Version history:
    1.0.0 - 2021-10-27 Function created
#>
Function Test-OGContainerPath {
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )
    Write-OGLogEntry "Checking for container at: '$($Path)'"
    $Exists = Test-Path "$Path" -PathType Container -ErrorAction SilentlyContinue
    If ($Exists) {
        Write-OGLogEntry "Container found at: '$($Path)'"
        Return $true
    }
    else {
        Write-OGLogEntry "No container found at: '$($Path)'" -logtype Warning
        Return $false
    }
}

<#
.SYNOPSIS
Check for file

.DESCRIPTION
Check for file

.PARAMETER Path
Path to file to check for

.EXAMPLE
Test-OGFilePath -Path C:\windows\folder\myfile.txt

.NOTES
    Name:       Test-OGFilePath 
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-10-27
    Updated:    -

    Version history:
    1.0.0 - 2021-10-27 Function created
#>
Function Test-OGFilePath {
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )
    Write-OGLogEntry "Checking for File at: '$($Path)'"
    $Exists = Test-Path "$Path" -PathType Leaf -ErrorAction SilentlyContinue
    If ($Exists) {
        Write-OGLogEntry "File found at: '$($Path)'"
        Return $true
    }
    else {
        Write-OGLogEntry "No file found at: '$($Path)'" -logtype Warning
        Return $false
    }
}

<#
.SYNOPSIS
Create new container/directory

.DESCRIPTION
Create new container/directory

.PARAMETER Path
Path to create new container/directory

.EXAMPLE
New-OGContainer -Path c:\Admin\Richie

.NOTES
    Name:       New-OGContainer 
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-10-27
    Updated:    -

    Version history:
    1.0.0 - 2021-10-27 Function created
#>
Function New-OGContainer {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )
    Write-OGLogEntry "Creating Container: '$Path'"
    try {
        New-Item "$Path" -ItemType Directory -Force | Out-Null
        $WasCreated = Test-OGContainerPath -Path $Path
        Return $WasCreated
    }
    catch {
        $message = "Failed creating registry key: '$Path'. Error: $_"
        Write-OGLogEntry $message -logtype Error
        throw $message
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
    $RemainingTime = $MaxWaitTime
    $count = 0
    Do {
        $status = Get-Process | Where-Object { $_.Name -like "$process" }
        If ($status) {
            $RemainingTime--
            Write-OGLogEntry "Waiting for process: '$($Process)' with PID: $($status.id) to close. Wait time remaining: $($RemainingTime)s" ; 
            $closed = $false
            Start-Sleep -Seconds 1
            $count++
        }        
        Else { 
            $closed = $true 
        }
    }
    Until (( $closed ) -or ( $count -eq $MaxWaitTime ))
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

.PARAMETER Kill
If the process is found within the time period forcefully stop it.

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
        [int]$MaxWaitTime = 60,
        [parameter(Mandatory = $false)]
        [switch]$Kill
    )
    $RemainingTime = $MaxWaitTime
    $count = 0
    Do {
        $status = Get-Process | Where-Object { $_.Name -like "$process" }
        If (!($status)) {
            $RemainingTime--
            Write-OGLogEntry "Waiting for process: $($Process) to start. Wait time remaining: $($RemainingTime)s" ; 
            $started = $false
            Start-Sleep -Seconds 1
            $count++
        }        
        Else { 
            $started = $true 
        }
    }
    Until (( $started ) -or ( $count -eq $MaxWaitTime ))
    if (($started)-and($count -eq 0)){
        Write-OGLogEntry "Process: '$($Process)' with PID: $($status.id) was found to be already running."
        if ($kill){
            Write-OGLogEntry "Kill switch set attempting to close: '$($Process)' with PID: $($status.id)"
            Stop-Process -InputObject $status -Force 
        }
        return $true
    }
    elseif (($started)-and($count -gt 0)){
        Write-OGLogEntry "Process: '$($Process)' with PID: $($status.id) has started."
        if ($kill){
            Write-OGLogEntry "Kill switch set attempting to close: '$($Process)' with PID: $($status.id)"
            Stop-Process -InputObject $status -Force
        }
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
Waits for a scheduled task to exit.

.DESCRIPTION
Checks for a scheduled task and then waits for that task to exit.

.PARAMETER TaskName
Name of scheduled Task to wait for.

.PARAMETER Timeout
Wait timeout in seconds. Default 300s

.PARAMETER loopTime
Log update frequency. Default 5s

.EXAMPLE
Wait-OGScheduledTask -TaskName "My Task Name"
Wait for a scheduled task with defualt wait time and looptime.

.EXAMPLE
Wait-OGScheduledTask -TaskName "My Task Name" -Wait 40 -looktime 1
Wait for a scheduled task with 40s wait time and 1s looptime.

.NOTES
    Name:       Wait-OGScheduledTask
    Author:     Richie Schuster - SCCMOG.com
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-01-24
    Updated:    -

    Version history:
        1.0.0 - 2022-01-24 Function created
#>
function Wait-OGScheduledTask{
    param(
        [Parameter(Mandatory = $true, Position = 0,ValueFromPipeline)]
        [string]$TaskName,
        [Parameter(Mandatory = $false, Position = 1,ValueFromPipeline)]
        [int]$Timeout = 300,
        [Parameter(Mandatory = $false, Position = 2,ValueFromPipeline)]
        [int]$loopTime = 5
    )
    $Task = Get-ScheduledTask | Where-Object {$_.TaskName -eq "$($TaskName)"}
    if (!($Task)){
        Write-OGLogEntry "Task not found with name. [Task Name: $($TaskName)]" -logtype Warning
        break
    }
    $timer =  [Diagnostics.Stopwatch]::StartNew()
    while (((Get-ScheduledTask  "$($Task.TaskName)").State -ne  'Ready') -and  ($timer.Elapsed.TotalSeconds -lt $Timeout)) {    
        Write-OGLogEntry "Waiting for scheduled task to complete [Task Name: $($Task.TaskName)] [Time Elapsed: $($timer.Elapsed.TotalSeconds)s] [Time Remaining: $($Timeout - $timer.Elapsed.TotalSeconds)s]"
        Start-Sleep -Seconds $loopTime
    }
    $timer.Stop()
    Write-OGLogEntry "Scheduled task has completed. [Task Name: $($Task.TaskName)] [Total Time: $($timer.Elapsed.TotalSeconds)s]"
}


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
    "Wait-OGProcessStart",
    "New-OGContainer",
    "Test-OGFilePath",
    "Test-OGContainerPath",
    "Export-OGFileDetailstoCSV",
    "New-OGMSEdgeProfile",
    "Start-OGCommand",
    "Get-OGFileLocation",
    "Get-OGFolderLocation",
    "Export-OGFileDetails",
    "Wait-OGScheduledTask"
)

foreach ($module in $Export){
    Export-ModuleMember $module
}
