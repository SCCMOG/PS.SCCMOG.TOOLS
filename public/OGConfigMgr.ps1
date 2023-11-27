##################################################################################################################################
# ConfigMgr Client Region
##################################################################################################################################

<#
.SYNOPSIS
Gets ConfigMgr SMS_InstalledSoftware Class and specific product if specified.

.DESCRIPTION
Gets ConfigMgr SMS_InstalledSoftware Class and specific product if specified.

.PARAMETER productName
If specified will return the WMI Instance of the Product Name if found to be in the SMS_InstalledSoftware

.PARAMETER WildCard
Places a wildcard * at the begining and end of the Product name.

.EXAMPLE
Get-OGSMSSoftwareList -productName "Adobe Acrobat DC"

    Returns:

    __SUPERCLASS               :
    __DYNASTY                  : SMS_InstalledSoftware
    __RELPATH                  : SMS_InstalledSoftware.SoftwareCode="{ac76ba86-1033-ffff-7760-0c0f074e4100}"
    __PROPERTY_COUNT           : 28
    __DERIVATION               : {}
    __SERVER                   : THISISMYMACHINENAME
    __NAMESPACE                : root\cimv2\sms
    __PATH                     : \\THISISMYMACHINENAME\root\cimv2\sms:SMS_InstalledSoftware.SoftwareCode="{ac76ba86-1033-ffff-7760-0c0f074e4100}"
    ARPDisplayName             : Adobe Acrobat DC
    ChannelCode                : 
    ChannelID                  :
    CM_DSLID                   :
    EvidenceSource             : BPXACAAAAXAAAACAXAAXAXXXX0
    InstallDate                : 20210909000000.000000+***
    InstallDirectoryValidation : 4
    InstalledLocation          : C:\Program Files (x86)\Adobe\Acrobat DC\
    InstallSource              : C:\Users\U6057906\Downloads\Acrobat_DC_Web_WWMUI\Adobe Acrobat\
    InstallType                : 0
    Language                   : 0
    LocalPackage               : C:\Windows\Installer\1a7460f.msi
    MPC                        :
    OsComponent                : 0
    PackageCode                : {B3F96825-BDC3-454C-9676-07B6DA02E9FC}
    ProductID                  : 16
    ProductName                : Adobe Acrobat DC
    ProductVersion             : 21.005.20060
    Publisher                  : Adobe Systems Incorporated
    RegisteredUser             : sccmog@sccmog.com
    ServicePack                :
    SoftwareCode               : {ac76ba86-1033-ffff-7760-0c0f074e4100}
    SoftwarePropertiesHash     : 9bd65b497146292f087323efe0beceb3c5ac4a19aaef657a19de612744fcb938
    SoftwarePropertiesHashEx   : 15bb5f3f116adb1e806ec4966ed4fdc7ab51fabe519a23bd7f771636443c7b1b
    UninstallString            : MsiExec.exe /I{AC76BA86-1033-FFFF-7760-0C0F074E4100}
    UpgradeCode                :
    VersionMajor               : 21
    VersionMinor               : 5
    PSComputerName             : THISISMYMACHINENAME

.EXAMPLE
Get-OGSMSSoftwareList -productName "Acrobat" -WildCard

    Returns:

    __SUPERCLASS               :
    __DYNASTY                  : SMS_InstalledSoftware
    __RELPATH                  : SMS_InstalledSoftware.SoftwareCode="{ac76ba86-1033-ffff-7760-0c0f074e4100}"
    __PROPERTY_COUNT           : 28
    __DERIVATION               : {}
    __SERVER                   : THISISMYMACHINENAME
    __NAMESPACE                : root\cimv2\sms
    __PATH                     : \\THISISMYMACHINENAME\root\cimv2\sms:SMS_InstalledSoftware.SoftwareCode="{ac76ba86-1033-ffff-7760-0c0f074e4100}"
    ARPDisplayName             : Adobe Acrobat DC
    ChannelCode                : 
    ChannelID                  :
    CM_DSLID                   :
    EvidenceSource             : BPXACAAAAXAAAACAXAAXAXXXX0
    InstallDate                : 20210909000000.000000+***
    InstallDirectoryValidation : 4
    InstalledLocation          : C:\Program Files (x86)\Adobe\Acrobat DC\
    InstallSource              : C:\Users\U6057906\Downloads\Acrobat_DC_Web_WWMUI\Adobe Acrobat\
    InstallType                : 0
    Language                   : 0
    LocalPackage               : C:\Windows\Installer\1a7460f.msi
    MPC                        :
    OsComponent                : 0
    PackageCode                : {B3F96825-BDC3-454C-9676-07B6DA02E9FC}
    ProductID                  : 16
    ProductName                : Adobe Acrobat DC
    ProductVersion             : 21.005.20060
    Publisher                  : Adobe Systems Incorporated
    RegisteredUser             : sccmog@sccmog.com
    ServicePack                :
    SoftwareCode               : {ac76ba86-1033-ffff-7760-0c0f074e4100}
    SoftwarePropertiesHash     : 9bd65b497146292f087323efe0beceb3c5ac4a19aaef657a19de612744fcb938
    SoftwarePropertiesHashEx   : 15bb5f3f116adb1e806ec4966ed4fdc7ab51fabe519a23bd7f771636443c7b1b
    UninstallString            : MsiExec.exe /I{AC76BA86-1033-FFFF-7760-0C0F074E4100}
    UpgradeCode                :
    VersionMajor               : 21
    VersionMinor               : 5
    PSComputerName             : THISISMYMACHINENAME

.EXAMPLE
Get-OGSMSSoftwareList -productPublisher "Adobe" -WildCard

.EXAMPLE
Get-OGSMSSoftwareList -productPublisher "Adobe" -productName "Adobe Acrobat DC"

.EXAMPLE
Get-OGSMSSoftwareList -productPublisher "Adobe" -productName "Acrobat" -WildCard

.EXAMPLE
Get-OGSMSSoftwareList

This command returns the entire SMS_InstalledSoftware Class.

.NOTES
    Name:       Get-OGSMSSoftwareList       
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2020-09-09
    Updated:    2020-09-10
    
    Version history:
    1.0.0 - 2020-09-09 Function created
    1.1.0 - 2020-09-10 Function created  
#>
function Get-OGSMSSoftwareList () {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$productName,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$productPublisher,
        [Parameter(Mandatory = $false)]
        [switch]$WildCard
    )
    if ($WildCard) {
        if ($productName) {
            $productName = "*$($productName)*"
            Write-OGLogEntry "Wildcard Specified productName: '$($productName)'"
        }
        if ($productPublisher) {
            $productPublisher = "*$($productPublisher)*"
            Write-OGLogEntry "Wildcard Specified productPublisher: '$($productPublisher)'"
        }
    }
    if (checkAdminRights){
    #Get all installed software
    try {
        Write-OGLogEntry "Getting WMI Class: 'SMS_InstalledSoftware' from NameSpace: 'root\cimv2\sms'."
        $SMS_InstalledSoftware = Get-WmiObject -Namespace 'root\cimv2\sms' -Class SMS_InstalledSoftware
        Write-OGLogEntry "Success getting WMI Class: 'SMS_InstalledSoftware' from NameSpace: 'root\cimv2\sms'."
    }
    catch {
        $message = "Failed to get WMI Class: 'SMS_InstalledSoftware' from NameSpace: 'root\cimv2\sms'. Error: $_"
        Write-OGLogEntry $message -logtype Error
        throw $message
    }
    ## Check the matches
    if (($productName)-or($productPublisher)){
        if (($productName)-and(!($productPublisher))) {
            Write-OGLogEntry "Searching for productName: '$($productName)'"
            $productInfo = $SMS_InstalledSoftware | Where-Object { $_.ARPDisplayName -like "$($productName)" }
        }
        elseif (($productPublisher)-and(!($productName))) {
            Write-OGLogEntry "Searching for productPublisher: '$($productPublisher)'"
            $productInfo = $SMS_InstalledSoftware | Where-Object { $_.Publisher -like "$($productPublisher)" }
        }
        elseif (($productPublisher) -and ($productName)) {
            Write-OGLogEntry "Searching for productName: '$($productName)' and productPublisher: '$($productPublisher)'"
            $productInfo = $SMS_InstalledSoftware | Where-Object { (($_.ARPDisplayName -like "$($productName)")-and($_.Publisher -like "$($productPublisher)")) }
        }
        if ($productInfo) {
            Write-OGLogEntry "Found instance(s) for the product returning."
            return $productInfo
        }
        Else {
            Write-OGLogEntry "Did not find instance(s) for $(if($productName){"Product: '$($productName)' "})$(if($productPublisher){"Publisher: '$($productPublisher)' "})returning False." -logtype Warning
            return $false
        }
    }
    Else {
        Write-OGLogEntry "No product specified returning complete class: SMS_InstalledSoftware." 
        return $SMS_InstalledSoftware
    }
    }
    else {
        $message = "Failed to get WMI Class: 'SMS_InstalledSoftware' from NameSpace: 'root\cimv2\sms'. User: '$([Security.Principal.WindowsIdentity]::GetCurrent())' does not have Administrator rights on: '$ENV:ComputerName'"
        #Write-OGLogEntry $message -logtype Error
        throw $message
    }
}

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

function Invoke-OGConfigMgrBaselines { 
$BaselineNames = "Clarivate - Zscaler Three","Clarivate - Zscaler Two"
$BaselineNames = $null
    param (
        [Parameter(Mandatory = $false, Position = 0)] 
        [String]$ComputerName = "$($ENV:COMPUTERNAME)",
        [Parameter(Mandatory = $False, Position = 1)] 
        [String[]]$BaselineNames
    )
    $objWMIBaselines = @()
    If ((($BaselineNames|Measure-Object).Count) -eq 0) {
        $objWMIBaselines = Get-WmiObject -ComputerName $ComputerName -Namespace root\ccm\dcm -Class SMS_DesiredConfiguration
    }
    Else {
        foreach ($baselineName in $BaselineNames){
            $objBaseline = $null
            $objBaseline = Get-WmiObject -ComputerName $ComputerName -Namespace root\ccm\dcm -Class SMS_DesiredConfiguration | Where-Object { $_.DisplayName -like $baselineName }
            if ($objBaseline){
                $objWMIBaselines += $objBaseline
            }
        }
    }
    $objWMIBaselines | ForEach-Object {
         ([wmiclass]"\\$ComputerName\root\ccm\dcm:SMS_DesiredConfiguration").TriggerEvaluation($_.Name, $_.Version) 
    }
}


##################################################################################################################################
# End ConfigMgr Client  Region
##################################################################################################################################


#Get-ChildItem function: | Where-Object { ($currentFunctions -notcontains $_)-and($_.Name -like "*-OG*") } | Select-Object -ExpandProperty name
$Export = @(
    "Invoke-OGHWInventory",
    #"Connect-ConfigMgr",
    "Get-OGSMSSoftwareList"
)

foreach ($function in $Export){
    Export-ModuleMember $function
}
