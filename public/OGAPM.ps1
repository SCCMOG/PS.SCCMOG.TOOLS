

<#
.SYNOPSIS
Clear registry entrys for the Auto Pilot Migration Scripts

.DESCRIPTION
Clear registry entrys for the Auto Pilot Migration Scripts

.PARAMETER APM_Module
APM Module

.PARAMETER APM_RegKey_Path
Path to APM RegKey

.EXAMPLE
Clear-OGAPMError -APM_Module "Inventory" -APM_RegKey_Path HKLM:\Software\SCCMOG\APM

.NOTES
    Name:       Clear-OGAPMError 
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-01-19
    Updated:    -

    Version history:
    1.0.0 - 2022-01-19 Function created
#>
function Clear-OGAPMError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$APM_Module,
        [Parameter(Mandatory = $false)]
        [string]$APM_RegKey_Path = "HKLM:\Software\SCCMOG\APM"
    )
    Write-OGLogEntry "Clearing APM errors for module: $($APM_Module)"
    if ($APM_Reg = Get-OGRegistryKey -RegKey $APM_RegKey_Path ){
        if ($APM_Reg.APM_Error_Module -eq $APM_Module){
            New-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "APM_Error" -Value "$false"
            New-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "APM_Error_Module" -Value "NONE"
            New-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "APM_Error_TimeStamp" -Value "NONE"
        } 
    }
    Remove-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "$($APM_Module)_Error"
    Remove-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "$($APM_Module)_ErrorTimeStamp"
    Write-OGLogEntry "Cleared APM errors for module: $($APM_Module)" -logtype Warning
}

<#
.SYNOPSIS
Write errors to registry for Auto Pilot Migration Scripts

.DESCRIPTION
Write errors to registry for Auto Pilot Migration Scripts

.PARAMETER ErrorMsg
Eror Message to write.

.PARAMETER APM_Module
APM Module

.EXAMPLE
New-OGAPMError -ErrorMsg "There has been an error" -APM_Module "Inventory"

.NOTES
    Name:       New-OGAPMError 
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-01-19
    Updated:    -

    Version history:
    1.0.0 - 2022-01-19 Function created
#>
function New-OGAPMError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ErrorMsg,
        [Parameter(Mandatory = $true)]
        [string]$APM_Module
    )
    $msg = "$($ErrorMsg)"
    Write-OGLogEntry $msg -logtype Error
    $ErrorTimeStamp = Get-Date -Format 'yyyy.MM.dd HH:mm:ss'
    New-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "APM_Error" -Value "$True"
    New-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "APM_Error_Module" -Value "$($APM_Module)"
    New-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "APM_Error_TimeStamp" -Value "$($ErrorTimeStamp)"
    New-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "$($APM_Module)_Error" -Value "$($msg)"
    New-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "$($APM_Module)_ErrorTimeStamp" -Value "$($ErrorTimeStamp)"
    New-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "$($APM_Module)_Complete" -Value "$($false)"
}

#Get-ChildItem function: | Where-Object { ($currentFunctions -notcontains $_)-and($_.Name -like "*-OG*") } | Select-Object -ExpandProperty name
$Export = @(
    "Clear-OGAPMError",
    "New-OGAPMError"
)

foreach ($module in $Export){
    Export-ModuleMember $module
}
#>
