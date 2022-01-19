# Name:              
# Author:     Richie Schuster - SCCMOG.com
# Website:    https://www.sccmog.com
# Contact:    @RichieJSY
# Created:    2021-08-17
# Updated:    -

# Version history:
# 1.0.0 - 2021-08-17 Function created
##################################################################################################################################
# Get Registry Region
##################################################################################################################################

<#
.SYNOPSIS
    Search a machines x6 and x86 Uninstall registry key for a specific Application (Appwiz.cpl) Name

.DESCRIPTION
    Search a machines x6 and x86 Uninstall registry key for a specific Application (Appwiz.cpl) Name

.PARAMETER ProductNames
    Application name(s)

.PARAMETER MachineName
    Machine to query.

.PARAMETER WildCard
    If entered will wildcard the application name. Front and back.

.PARAMETER Log
    Write results to logfile.

.EXAMPLE
        PS C:\> Get-OGProductUninstallKey -ProductNames "McAfee VirusScan Enterprise"
        Exact Add remove programs name or appname local machine
.EXAMPLE
        PS C:\> Get-OGProductUninstallKey -ProductNames "McAfee VirusScan Enterprise" -MachineName "SERVERNAME"
        Exact Add remove programs name or appname remote (can add FQDN if required)
.EXAMPLE
        PS C:\> Get-OGProductUninstallKey -ProductNames "McAfee" -WildCard
        Wild card app name local machine
.EXAMPLE
        PS C:\> Get-OGProductUninstallKey -ProductNames "McAfee" -MachineName "SERVERNAME" -WildCard
        Wild card app name remote (can add FQDN if required)

.NOTES
    Name:       Get-OGProductUninstallKey 
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-08-17
    Updated:    -

    Version history:
    1.0.0 - 2021-08-17 Function created
#>
function Get-OGProductUninstallKey {
    [cmdletbinding()]            
    param(                    
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ProductNames,
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$MachineName = $ENV:COMPUTERNAME,
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [switch]$WildCard,
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [switch]$log             
    )
    $RetrievedProducts = New-Object System.Collections.Generic.List[System.Object]
    try {
        $OSArch = (Get-WMIObject -ClassName Win32_OperatingSystem -ComputerName $MachineName).OSArchitecture
    }
    catch [System.Exception] {
        Write-CMTLog -Value "Error when getting OS Arch from $($MachineName). Error: $($_.Exception.Message)"
    }
    try {
        $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $MachineName)
    }
    catch [System.Exception] {
        Write-CMTLog -Value "Error opening remote registry for machine: $($MachineName). Error: $($_.Exception.Message)"
    }
    switch ($OSArch) {
        "64-bit" { 
            $UninstallRegKeys = @('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
                'SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\\Uninstall'
            )
        }
        Default {
            $UninstallRegKeys = @('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall')
        }
    }
    foreach ($uninstkey in $UninstallRegKeys) {
        $RegKey = $Reg.OpenSubKey("$uninstkey")
        $SubkeyNames = $RegKey.GetSubKeyNames()
        foreach ($subkey in $SubkeyNames) {
            $Key = $Reg.OpenSubKey("$($uninstkey)\$($subkey)")
            foreach ($product in $productNames) {
                if ($Wildcard) {
                    $product = "*$($product)*"
                }
                if ($key.GetValue("DisplayName") -like "$($product)") {
                    if ($key.Name -like "HKEY_LOCAL_MACHINE*") {
                        $PSDriveKeyPath = ($key.Name).Replace("HKEY_LOCAL_MACHINE", "HKLM:")
                    }
                    if ($key.Name -like "HKEY_CURRENT_USER*") {
                        $PSDriveKeyPath = ($key.Name).Replace("HKEY_CURRENT_USER", "HKCU:")
                    }
                    $MatchProduct = [pscustomobject]@{
                        KeyName         = $key.Name.split('\')[-1];
                        KeyPath         = $PSDriveKeyPath;
                        DisplayName     = $key.GetValue("DisplayName");
                        DisplayVersion  = $key.GetValue("DisplayVersion");
                        Publisher       = $key.GetValue("Publisher");
                        UninstallString = $key.GetValue("UninstallString");
                        InstallLocation = $key.GetValue("InstallLocation");
                    }
                    $RetrievedProducts.Add($MatchProduct)
                }
            }
        }
    }
    if ($RetrievedProducts) {
        if ($Log) {
            Write-OGLogEntry -logText "Machine: $($MachineName)"
            Write-OGLogEntry -logText "Products found:"
            Write-OGLogEntry -logText "-------------"
            foreach ($product in $RetrievedProducts) {
                $Product.psobject.properties | ForEach-Object { Write-CMTLog -Value "$($_.Name):   $($_.Value)" }
                Write-OGLogEntry -logText "-------------"
            }
        } 
        return $RetrievedProducts
    }
    else {
        return $false
    }
}

<#
.SYNOPSIS
Check if Registry Key Exists

.DESCRIPTION
Check if Registry Key Exists

.PARAMETER RegKey
RegKey to check for

.EXAMPLE
Test-OGRegistryKey -RegKey HKLM:\Software\SCCMOG

.NOTES
    Name:       Test-OGRegistryKey 
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-10-27
    Updated:    -

    Version history:
    1.0.0 - 2021-10-27 Function created
#>
Function Test-OGRegistryKey {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RegKey
    )
    Write-OGLogEntry "Checking for RegKey: '$RegKey'"
    $Exists = Get-Item -Path "$RegKey" -ErrorAction SilentlyContinue
    If ($Exists) {
        Write-OGLogEntry "Found RegKey: '$RegKey'"
        Return $true
    }
    else {
        Write-OGLogEntry "Did not find RegKey: '$RegKey'"
        Return $false
    }
}

<#
.SYNOPSIS
Create Regkey

.DESCRIPTION
Create Regkey

.PARAMETER RegKey
RegKey to create

.EXAMPLE
New-OGRegistryKey -RegKey HKLM:\Software\SCCMOG

.NOTES
    Name:       New-OGRegistryKey 
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-10-27
    Updated:    -

    Version history:
    1.0.0 - 2021-10-27 Function created
#>
Function New-OGRegistryKey {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RegKey
    )
    Write-OGLogEntry "Creating RegKey: '$RegKey'"
    try {
        New-Item "$RegKey" -ItemType Directory -Force | Out-Null
        $WasCreated = Test-OGRegistryKey -RegKey $RegKey
        Return $WasCreated
    }
    catch {
        $message = "Failed creating registry key: '$RegKey'. Error: $_"
        Write-OGLogEntry $message -logtype Error
        throw $message
    }
}

<#
.SYNOPSIS
Get the registry key properties and values

.DESCRIPTION
Get the registry key properties and values

.PARAMETER RegKey
RegKey to get

.EXAMPLE
Get-OGRegistryKey -RegKey HKLM:\Software\SCCMOG

.NOTES
    Name:       Get-OGRegistryKey 
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-10-27
    Updated:    -

    Version history:
    1.0.0 - 2021-10-27 Function created
#>
Function Get-OGRegistryKey {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RegKey
    )
    $Exists = Test-OGRegistryKey -RegKey "$RegKey" -ErrorAction SilentlyContinue
    If ($Exists) {
        Write-OGLogEntry "Getting RegKey '$RegKey'"
        $data = Get-ItemProperty -Path $RegKey
        Return $data
    }
    else {
        return $Exists
    }
}

<#
.SYNOPSIS
Check for regkey item.

.DESCRIPTION
Check for regkey item.

.PARAMETER RegKey
Regkey to check for item.

.PARAMETER Name
Regkey Item to check for.

.EXAMPLE
Test-OGRegistryKeyItem -RegKey HKLM:\Software\SCCMOG -Name APM

.NOTES
    Name:       Test-OGRegistryKeyItem 
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-10-27
    Updated:    -

    Version history:
    1.0.0 - 2021-10-27 Function created
#>
Function Test-OGRegistryKeyItem {
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RegKey,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [parameter(DontShow=$true)]
        [switch]$NoLogging
    )
    #Test-OGRegistryKeyItem -RegKey $AP_Migration_Key_Path -Name "OoB_Files_LastRun"
    try {
        if (Test-OGRegistryKey -RegKey $RegKey) {
            Write-OGLogEntry "Checking for Property: '$($Name)' at '$($RegKey)'"
            Get-OGRegistryKey -RegKey $RegKey | Select-Object -ExpandProperty $Name -ErrorAction Stop | Out-Null
            Write-OGLogEntry "Found Registry Key Item: '$($Name)' at '$($RegKey)'"
            return $true
        }
        else {
            Return $false
        }
    }
    catch {
        Write-OGLogEntry "Did not find Registry Key Item: '$($Name)' at '$($RegKey)'"
        return $false
    }
} 

<#
.SYNOPSIS
New Regkey Item

.DESCRIPTION
New Regkey Item

.PARAMETER RegKey
Regkey to create the new item

.PARAMETER Name
Name of the new item.

.PARAMETER Value
Value of the new item.

.PARAMETER Type
Tpye of the new item.

.EXAMPLE
New-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "BackupRequired" -Value "False"

.EXAMPLE
New-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "BackupComplete" -Value 0 -Type DWord

.NOTES
    Name:       New-OGRegistryKeyItem 
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-10-27
    Updated:    -

    Version history:
    1.0.0 - 2021-10-27 Function created
#>
Function New-OGRegistryKeyItem {
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RegKey,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Value,
        [parameter(Mandatory = $false)]
        [ValidateSet("String", "ExpandString", "Binary", "DWord", "MultiString", "Qword", "Unknown")]
        [string]$Type = "String"
    )
    Write-OGLogEntry "Creating RegKey Item: '$($Name)' Value: '$($Value)' Type: '$($type)'"
    try {
        New-ItemProperty -Path "$RegKey" -Name $Name -Value $Value -PropertyType $Type -Force  | Out-Null
        $WasCreated = Test-OGRegistryKeyItem -RegKey $RegKey -Name $Name
        Return $WasCreated
    }
    catch {
        $message = "Failed to create RegKey Item: '$($Name)' Value: '$($Value)' Type: '$($type)'. Error message: $_"
        Write-OGLogEntry $message -logtype Error
        throw $message
    }
}


<#
.SYNOPSIS
Remove Regkey Item

.DESCRIPTION
Remove Regkey Item

.PARAMETER RegKey
Regkey to create the new item

.PARAMETER Name
Name of the new item.

.PARAMETER Type
Type of the new item.

.EXAMPLE
Remove-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "BackupRequired"

.NOTES
    Name:       Remove-OGRegistryKeyItem 
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-01-19
    Updated:    -

    Version history:
    1.0.0 - 2022-01-19 Function created
#>
Function Remove-OGRegistryKeyItem {
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RegKey,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
    Write-OGLogEntry "Removing RegKey Item: '$($Name)' Path: '$($RegKey)'" -logtype Warning
    try {
        if(Test-OGRegistryKeyItem -RegKey $RegKey -Name $Name){
            Remove-ItemProperty -Path "$RegKey" -Name $Name -Force  | Out-Null
            $WasRemoved = Test-OGRegistryKeyItem -RegKey $RegKey -Name $Name
            if (!($WasRemoved)){
                Write-OGLogEntry "Success removing RegKey Item: '$($Name)' Path: '$($RegKey)'"
                return $true
            }
        }
        else{
            Write-OGLogEntry "No need to execute removal."
            return $true
        }
    }
    catch {
        $message = "Failed to create RegKey Item: '$($Name)' Value: '$($Value)' Type: '$($type)'. Error message: $_"
        Write-OGLogEntry $message -logtype Error
        throw $message
    }
}

##################################################################################################################################
# End Get Registry Region
##################################################################################################################################


#Get-ChildItem function: | Where-Object { ($currentFunctions -notcontains $_)-and($_.Name -like "*-OG*") } | Select-Object -ExpandProperty name
$Export = @(
    "Test-OGRegistryKey",
    "New-OGRegistryKey",
    "Get-OGRegistryKey",
    "Test-OGRegistryKeyItem",
    "New-OGRegistryKeyItem",
    "Remove-OGRegistryKeyItem"
)

foreach ($module in $Export){
    Export-ModuleMember $module
}
