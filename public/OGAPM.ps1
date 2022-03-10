

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
Clear-OGAPMIssue -APM_Module "Inventory" -APM_RegKey_Path HKLM:\Software\SCCMOG\APM

.NOTES
    Name:       Clear-OGAPMIssue 
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-01-19
    Updated:    -

    Version history:
    1.0.0 - 2022-01-19 Function created
#>
function Clear-OGAPMIssue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$APM_Module,
        [Parameter(Mandatory = $false)]
        [string]$APM_RegKey_Path = "HKLM:\Software\SCCMOG\APM"
    )
    Write-OGLogEntry "Clearing APM issues for module: $($APM_Module)"
    if ($APM_Reg = Get-OGRegistryKey -RegKey $APM_RegKey_Path){
        if ($APM_Reg.APM_Error_Module -eq $APM_Module){
            Remove-ItemProperty -Path $APM_RegKey_Path -Name "APM_Error" -Force -ErrorAction SilentlyContinue | Out-Null
            Remove-ItemProperty -Path $APM_RegKey_Path -Name "APM_Error_Module" -Force -ErrorAction SilentlyContinue | Out-Null
            Remove-ItemProperty -Path $APM_RegKey_Path -Name "APM_Error_TimeStamp" -Force -ErrorAction SilentlyContinue | Out-Null
            # New-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "APM_Error" -Value "$false"
            # New-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "APM_Error_Module" -Value "NONE"
            # New-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "APM_Error_TimeStamp" -Value "NONE"
        } 
    }
    Remove-ItemProperty -Path $APM_RegKey_Path -Name "$($APM_Module)_Error" -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-ItemProperty -Path $APM_RegKey_Path -Name "$($APM_Module)_ErrorTimeStamp" -Force -ErrorAction SilentlyContinue | Out-Null
    # Remove-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "$($APM_Module)_Error"
    # Remove-OGRegistryKeyItem -RegKey $APM_RegKey_Path -Name "$($APM_Module)_ErrorTimeStamp"
    Write-OGLogEntry "Cleared APM issues for module: $($APM_Module)"
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

.PARAMETER throw
throw the current execution also.

.EXAMPLE
New-OGAPMIssue -ErrorMsg "There has been an error" -APM_Module "Inventory"

.EXAMPLE
New-OGAPMIssue -ErrorMsg "There has been an error" -APM_Module "Inventory" -throw

.NOTES
    Name:       New-OGAPMIssue 
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-01-19
    Updated:    -

    Version history:
    1.0.0 - 2022-01-19 Function created
#>
function New-OGAPMIssue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ErrorMsg,
        [Parameter(Mandatory = $true)]
        [string]$APM_Module,
        [Parameter(Mandatory = $false)]
        [string]$RegKey = "HKLM:\SOFTWARE\SCCMOG\APM",
        [Parameter(Mandatory = $false)]
        [switch]$throw
    )
    $msg = "$($ErrorMsg)"
    Write-OGLogEntry $msg -logtype Error
    $ErrorTimeStamp = Get-Date -Format 'yyyy.MM.dd HH:mm:ss'
    New-OGRegistryKeyItem -RegKey $RegKey -Name "APM_Error" -Value "$True"
    New-OGRegistryKeyItem -RegKey $RegKey -Name "APM_Error_Module" -Value "$($APM_Module)"
    New-OGRegistryKeyItem -RegKey $RegKey -Name "APM_Error_TimeStamp" -Value "$($ErrorTimeStamp)"
    New-OGRegistryKeyItem -RegKey $RegKey -Name "$($APM_Module)_Error" -Value "$($msg)"
    New-OGRegistryKeyItem -RegKey $RegKey -Name "$($APM_Module)_ErrorTimeStamp" -Value "$($ErrorTimeStamp)"
    New-OGRegistryKeyItem -RegKey $RegKey -Name "$($APM_Module)_Complete" -Value "$($false)"
    if ($throw){
        Write-OGLogEntry -logtype Footer
        throw $msg
    }
}

#Get-ChildItem function: | Where-Object { ($currentFunctions -notcontains $_)-and($_.Name -like "*-OG*") } | Select-Object -ExpandProperty name
$Export = @(
    "Clear-OGAPMIssue",
    "New-OGAPMIssue"
)

foreach ($module in $Export){
    Export-ModuleMember $module
}
#>
