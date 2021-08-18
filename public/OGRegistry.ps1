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
    Type:           String Array
    Required:       True
    Description:    Application name(s)

.PARAMETER MachineName
    Type:           String Array
    Required:       True
    Default:        $:ENV:ComputerName
    Description:    Application name(s)

.PARAMETER WildCard
    Type:           switch
    Required:       false
    Description:    If entered will wildcard the application name. Front and back.

.PARAMETER Log
    Type:           switch
    Required:       false
    Description:    Write results to logfile.

.EXAMPLE
    Exact Add remove programs name or appname local machine
        Get-OGProductUninstallKey -ProductNames "McAfee VirusScan Enterprise"
    Exact Add remove programs name or appname remote (can add FQDN if required)
        Get-OGProductUninstallKey -ProductNames "McAfee VirusScan Enterprise" -MachineName "JSY-CCMSVRVP001"
    Wild card app name local machine
        Get-OGProductUninstallKey -ProductNames "McAfee" -WildCard
    Wild card app name remote (can add FQDN if required)
        Get-OGProductUninstallKey -ProductNames "McAfee" -MachineName "JSY-CCMSVRVP001" -WildCard

.NOTES
    Name:       Get-OGProductUninstallKey 
    Author:     Richie Schuster - SCCMOG.com
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
##################################################################################################################################
# End Get Registry Region
##################################################################################################################################
