##################################################################################################################################
# ConfigMgr Client Region
##################################################################################################################################

<#
.SYNOPSIS
    Invoke a Hardware Inventory from the SCCM/MEMCM Client on the machine

.DESCRIPTION
    Invoke a Hardware Inventory from the SCCM/MEMCM Client on the machine. A Full or delta can be performed.

.PARAMETER Full
If specified will force remove any Hardware Inventory Data on the machine and re run.

.EXAMPLE
    PS C:\> Invoke-OGHWInventory
    Runs a delta HW Inventory ontop of what is currently available in WMI.

.EXAMPLE
    PS C:\> Invoke-OGHWInventory -Full
    Clears current HW Inventory WMI and re runs.

.NOTES
    Name:        Invoke-HWInventory       
    Author:      Richie Schuster - SCCMOG.com
    Website:     https://www.sccmog.com
    GitHub:      https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Contact:     @RichieJSY
    Created:     2020-30-07
    Updated:     -
    
    Version history:
    1.0.0 - (2020-30-07) Function created
#>
function Invoke-OGHWInventory {
    param(
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [switch]$Full
    )
    $HardwareInventoryID = '{00000000-0000-0000-0000-000000000001}'
    If ($Full) {
        Write-OGLogEntry -logText "Clearing current local HW DB to publish full."
        Get-WmiObject -Namespace 'Root\CCM\INVAGT' -Class 'InventoryActionStatus' -Filter "InventoryActionID='$HardwareInventoryID'" | Remove-WmiObject
        Write-OGLogEntry -logText "Success - clearing current HW DB to pulish full."
        Start-Sleeper -Seconds 5
    }
    Write-OGLogEntry -logText "Invoking HW inventory."
    Invoke-WmiMethod -Namespace root\CCM -Class SMS_Client -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000001}" | Out-Null
    Write-OGLogEntry -logText "Success invoking HW inventory."
}
##################################################################################################################################
# End ConfigMgr Client  Region
##################################################################################################################################
