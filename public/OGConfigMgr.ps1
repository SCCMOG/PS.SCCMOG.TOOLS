##################################################################################################################################
# ConfigMgr Client Region
##################################################################################################################################

<#
.SYNOPSIS
    Connects to ConfigMgr Powershell Drive.
.DESCRIPTION
    Connects to ConfigMgr Powershell Drive.
.EXAMPLE
    PS C:\> Connect-ConfigMgr -SiteCode "CLV" -ProviderMachineName "SCCM-SJC1.mm-ads.com"
    Connects to the ConfigMgr Site with Code: CLV using the SiteServer SCCM-SJC1.mm-ads.com
.PARAMETER SiteCode
    SiteCode to connect to.
.PARAMETER ProviderMachineName
    Primary or CAS to use to connect to the SiteCode.
.PARAMETER initParams
    Hashtable of initialising parameters.
.NOTES
    Name:       Connect-ConfigMgr       
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2020-08-25
    Updated:    -
    
    Version history:
    1.0.0 - 2020-08-25 Function created
#>
function Connect-ConfigMgr(){
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true,HelpMessage="Site code for site to connect to.")]
        [string]$SiteCode,
        [Parameter(Mandatory=$true,HelpMessage="FQDN of site server to connect to.")]
        [string]$ProviderMachineName,
        [Parameter(Mandatory=$false,HelpMessage="Hashtable of parameters for initialisation.")]
        [hashtable]$initParams
    )
    Write-OGLogEntry "Attempting to import the ConfigMgr Module. SiteCode: $($SiteCode) ProviderMachineName: $($ProviderMachineName)"
    try{
        if((Get-Module ConfigurationManager) -eq $null) {
            Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" @initParams 
        }
        if((Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
            New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName @initParams
        }
        Set-Location "$($SiteCode):\" @initParams
        Write-OGLogEntry "Success importing the ConfigMgr Module. SiteCode: $($SiteCode) ProviderMachineName: $($ProviderMachineName)"
        return $true
    }
    catch{
        $message = "Failed importing the ConfigMgr Module. SiteCode: $($SiteCode) ProviderMachineName: $($ProviderMachineName). Error: $_"
        Write-OGLogEntry $message -logtype Error
        Throw $message
    }    
}

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
    Name:       Invoke-HWInventory       
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2020-30-07
    Updated:    -
    
    Version history:
    1.0.0 - (2020-30-07) Function created
#>
function Invoke-OGHWInventory {
    [cmdletbinding()]
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


#Get-ChildItem function: | Where-Object { ($currentFunctions -notcontains $_)-and($_.Name -like "*-OG*") } | Select-Object -ExpandProperty name
$Export = @(
    "Invoke-OGHWInventory",
    "Connect-ConfigMgr"
)

foreach ($function in $Export){
    Export-ModuleMember $function
}
