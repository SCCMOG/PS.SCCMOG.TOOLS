
<#
.SYNOPSIS
    Gets all recursive members of the Azure group name supplied.
.DESCRIPTION
    Gets all recursive members of the Azure group name supplied.
.EXAMPLE
    PS C:\> Get-OGRecursiveAADGroupMemberUsers -AzureGroupName "My Azure Group Name"
    Gets all recursive members of the Azure group name supplied.
    Parse returned data using Select-OGUnique function to get all unique objects :)
.PARAMETER AzureGroupName
    Name of the Azure group that you would like to get all recursive members for.
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    Name:       Get-OGRecursiveAADGroupMemberUsers
    Author:     Richie Schuster - SCCMOG.com
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-08-24
    Updated:    -

    Version history:
        1.0.0 - 2021-08-24 Function created
#>
Function Get-OGRecursiveAADGroupMemberUsers{
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$True,ValueFromPipeline=$true)]
        [string]$AzureGroupName,
        [parameter(DontShow)]
        $stack
    )
    Begin{
        if (!($stack)){$stack = @()}
        try{
            Get-AzureADCurrentSessionInfo -ErrorAction SilentlyContinue
        }
        catch{
            try{
                Write-Warning "Connect to Azure AD."
                Connect-AzureAD -ErrorAction Stop
            }
            catch{
                Throw "Failed to connect to Azure AD. Error: $_"
            }
        }
    }
    Process {
        try{
            $AzureGroup = Get-AzureADGroup -SearchString "$AzureGroupName" -ErrorAction Stop
            $stack += $AzureGroupName
            if($AzureGroup){
                $logText = $stack -join " | "
                Write-OGLogEntry "Enumerating: '$($logText)'"
                $Members = Get-AzureADGroupMember -ObjectId $AzureGroup.ObjectId -All $true -ErrorAction Stop
                $UserMembers = $Members | Where-Object{$_.ObjectType -eq 'User'}
                If($Members | Where-Object{$_.ObjectType -eq 'Group'}){
                    $UserMembers += $Members | Where-Object{$_.ObjectType -eq 'Group'} | ForEach-Object{ Get-OGRecursiveAADGroupMemberUsers -AzureGroupName $_.DisplayName -stack $stack}
                }
                Write-OGLogEntry "Total User count for: '$($logText)' Count: $($UserMembers.Count)"
            }
            else{
                $message = "No AAD group found with name: '$($AzureGroupName)'"
                Write-OGLogEntry $message -logtype Error
                Throw $message
            }    
        }
        catch{
            $message = "Failed during enumeration of AAD group: '$($AzureGroupName)'. Error: $_"
            Write-OGLogEntry $message -logtype Error
            Throw $message
        }
    }
    end {
        Return $UserMembers
    }
}


<#
.SYNOPSIS
Download the sysinternals Handle Application

.DESCRIPTION
Download the sysinternals Handle Application from https://download.sysinternals.com/files/Handle.zip

.PARAMETER Output_Path
Path to extract the sysinternals Handle Application downloaded from https://download.sysinternals.com/files/Handle.zip

.EXAMPLE
Get-OGHandleApp -Output_Path "$global:PS_OG_ModuleRoot\Tools\Handle"

.NOTES
    Name:       Get-OGHandleApp
    Original:   https://www.powershellgallery.com/packages/LockingProcessKiller/0.9.0/Content/LockingProcessKiller.psm1
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-03-14
    Updated:    -

    Version history:
    1.0.0 - 2022-03-14 Function Created
#>
function Get-OGHandleApp{
    param (
        [Parameter(Mandatory = $false,Position = 0)]
        [string] $Output_Path = "$global:PS_OG_ModuleRoot\Tools\Handle"
    )
    $ZipFile = "Handle.zip"
    $ZipFilePath = "$Output_Path\$ZipFile"
    $Uri = "https://download.sysinternals.com/files/$ZipFile"
    try {
        if (!(Test-Path "$($Output_Path)" -PathType Container)){
            $null = New-Item -ItemType Directory -Path $Output_Path -Force -ErrorAction Stop
        }
        Invoke-RestMethod -Method Get -Uri $Uri -OutFile $ZipFilePath -ErrorAction Stop
        Expand-Archive -Path $ZipFilePath -DestinationPath $Output_Path -Force -ErrorAction Stop
        Remove-Item -Path $ZipFilePath -ErrorAction SilentlyContinue
        if (Test-Path "$($Output_Path)\Handle.exe" -PathType Leaf){
            return "$Output_Path\Handle.exe"
        }
        Else{
            return $false
        }
    }
    catch {
        Remove-Item -Path $Output_Path -Recurse -Force -ErrorAction SilentlyContinue
        Throw "Failed to download dependency: handle.exe from: $Uri"
    }
}

##
<#
.SYNOPSIS
    Get Warranty data for a Dell machine

.DESCRIPTION
    Get Warranty data for a Dell machine and return it as a hash table

.PARAMETER serialNumber
    Serial number of machine

.PARAMETER DellClientID
    Dell client ID provided by Dell 

.PARAMETER DellAPIKey
    Dell API Key provided by Dell 

.PARAMETER Client
    Org Name - Default SCCMOG

.EXAMPLE
    Get-OGDellWarranty -serialNumber $serialNumber -DellClientID $dellClientID -DellAPIKey $dellAPIKey
    Returns the warranty data for the serial number provided as a hash table

.EXAMPLE
    Get-OGDellWarranty -serialNumber $serialNumber -DellClientID $dellClientID -DellAPIKey $dellAPIKey -Client "YourOrgName"
    Returns the warranty data for the serial number provided as a hash table and also adds your Organisation name.

.NOTES
    Name:       Get-OGDellWarranty
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-05-19
    Updated:    -

    Version history:
    1.0.0 - 2022-05-19 Function Created
#>
function Get-OGDellWarranty {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $serialNumber, 
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $DellClientID,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $DellAPIKey,
        [Parameter(Mandatory = $false)]
        $Client = "SCCMOG"
    )
    $vendor = "Dell"
    $AuthURI = "https://apigtwb2c.us.dell.com/auth/oauth/v2/token"
    $OAuth = "$DellClientID`:$DellAPIKey"
    $dellAPIUri = "https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-entitlements"
    try {      
        $Bytes = [System.Text.Encoding]::ASCII.GetBytes($OAuth)
        $EncodedOAuth = [Convert]::ToBase64String($Bytes)
        $headersAuth = @{ "authorization" = "Basic $EncodedOAuth" }
        $Authbody = 'grant_type=client_credentials'
        Write-OGLogEntry "Retrieving Warranty authentication token from $($vendor) [AuthURI: $($AuthURI)]"
        $AuthResult = Invoke-RESTMethod -Method Post -Uri $AuthURI -Body $AuthBody -Headers $HeadersAuth
        Write-OGLogEntry "Success retrieving Warranty authentication token from $($vendor) [AuthURI: $($AuthURI)]"
        $headersReq = @{ "Authorization" = "Bearer $($AuthResult.access_token)" }
        $ReqBody = @{ servicetags = $serialNumber }
        Write-OGLogEntry "Retrieving Warranty data from $($vendor) for machine [Serial: $($serialNumber)][APIUri: $($dellAPIUri)]"
        $objResult = Invoke-RestMethod -Uri "$($dellAPIUri)" -Headers $headersReq -Body $ReqBody -Method Get -ContentType "application/json"
        if ($objResult.entitlements.serviceleveldescription) {
            Write-OGLogEntry "Success retrieving Warranty data from $($vendor) for machine [Serial: $($serialNumber)][APIUri: $($dellAPIUri)]"
            $objWarranty = [System.Collections.IDictionary]@{
                'serial'       = $serialNumber
                'serviceLevel' = $objResult.entitlements.serviceleveldescription -join ", "
                'startDate'    = ([datetime](($objResult.entitlements.startdate | sort-object -Descending | select-object -last 1) -split 'T')[0]).ToString("yyyy-MM-dd")
                'endDate'      = ([datetime](($objResult.entitlements.enddate | sort-object | select-object -last 1) -split 'T')[0]).ToString("yyyy-MM-dd")
                'vendor'       = "$($vendor)"
                'client'       = $Client
            }
            return $objWarranty
        }
        else {
            Write-OGLogEntry "Failed retrieving $($vendor) Warranty information for machine [Serial: $($serialNumber)][Result: $($objResult)]." -logtype Error
            return $false
        }
    }
    catch [System.Exception] {
        Write-OGLogEntry "Failed retrieving $($vendor) Warranty information for machine [Serial: $($serialNumber)]. Error Message: $($_.Exception.Message)" -logtype Error
        return $false
    }     
}


<#
.SYNOPSIS
    Get Warranty data for a Lenovo machine

.DESCRIPTION
    Get Warranty data for a Lenovo machine and return it as a hash table

.PARAMETER serialNumber
    Serial number of machine

.PARAMETER lenovoAPIKey
    API Key provided by Lenovo Account Manager

.PARAMETER IncudeBatteryExpiration
    Not used currently.

.PARAMETER Client
    Org Name - Default SCCMOG

.EXAMPLE
    Get-OGLenovoWarranty -serialNumber $serialNumber -lenovoAPIKey $lenovoAPIKey
    Returns the warranty data for the serial number provided as a hash table

.EXAMPLE
    Get-OGLenovoWarranty -serialNumber $serialNumber -lenovoAPIKey $lenovoAPIKey -Client "$($orgName)"
    Returns the warranty data for the serial number provided as a hash table and also adds your Organisation name.

.NOTES
    Name:       Get-OGLenovoWarranty
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-05-19
    Updated:    -

    Version history:
    1.0.0 - 2022-05-19 Function Created
#>
Function Get-OGLenovoWarranty { 
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$serialNumber, 
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$lenovoAPIKey,
        [Parameter(Mandatory = $false)]
        [switch]$IncudeBatteryExpiration,
        [Parameter(Mandatory = $false)]
        [string]$Client = "SCCMOG"
    ) 
    $vendor = "Lenovo"
    $lenovoAPIUri = "http://supportapi.$($vendor).com/V2.5/Warranty?Serial="
    $headers = @{
        'ClientId' = $lenovoAPIKey
    };
    Try {
        Write-OGLogEntry "Retrieving Warranty data from $($vendor) for machine [Serial: $($serialNumber)][APIUri: $($lenovoAPIUri)$($SerialNumber)]"
        $objResult = Invoke-RestMethod -Uri "$($lenovoAPIUri)$($SerialNumber)" -Headers $headers;
        Write-OGLogEntry "Success retrieving $($vendor) Warranty information for machine [Serial: $($serialNumber)][APIUri: $($lenovoAPIUri)$($SerialNumber)]"
        If ($IncudeBatteryExpiration) {
            Write-OGLogEntry "Battey Warranty information requested also."
            $objWarrantyResult = $objResult.Warranty | Where-Object { ($_.ID -like "1EZ*") -or ($_.ID -eq "36Y") -or ($_.ID -eq "3EZ") }
        }
        else {
            $objWarrantyResult = $objResult.Warranty | Where-Object { ($_.ID -eq "36Y") -or ($_.ID -eq "3EZ") }    
        }
        if ($objWarrantyResult.Type) {
            $objWarranty = [System.Collections.IDictionary]@{
                'serial'       = $serialNumber
                'serviceLevel' = $objWarrantyResult.Type
                'startDate'    = ([datetime](($objWarrantyResult.Start | sort-object -Descending | select-object -last 1) -split 'T')[0]).ToString("yyyy-MM-dd")
                'endDate'      = ([datetime](($objWarrantyResult.End  | sort-object | select-object -last 1) -split 'T')[0]).ToString("yyyy-MM-dd")
                'vendor'       = "$($vendor)"
                'client'       = $Client
            }
            return $objWarranty
        }
        else {
            Write-OGLogEntry "Failed retrieving $($vendor) Warranty information for machine [Serial: $($serialNumber)][APIUri: $($lenovoAPIUri)$($SerialNumber)]. Error Message: $($_.Exception.Message)" -logtype Error
            return $false
        }
        Write-OGLogEntry "Returning Warranty information..."
        
    }
    catch [System.Exception] {
        Write-OGLogEntry "Failed retrieving $($vendor) Warranty information for machine [Serial: $($serialNumber)][APIUri: $($lenovoAPIUri)$($SerialNumber)]. Error Message: $($_.Exception.Message)" -logtype Error
        return $false
    }     
}


#Get-ChildItem function: | Where-Object { ($currentFunctions -notcontains $_)-and($_.Name -like "*-OG*") } | Select-Object -ExpandProperty name
$Export = @(
    "Get-OGRecursiveAADGroupMemberUsers",
    "Get-OGHandleApp",
    "Get-OGDellWarranty",
    "Get-OGLenovoWarranty"
)

foreach ($module in $Export){
    Export-ModuleMember $module
}

<#
function saveRepo {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Owner = "SCCMOG" ,
        [Parameter(Mandatory = $false)]
        [string]$Project = "PS.SCCMOG.TOOLS",
        [Parameter(Mandatory = $false)]
        [string]$Branch = "main",
        [Parameter(Mandatory = $false)]
        [string]$DownloadPath = "$(Split-Path $script:MyInvocation.MyCommand.Path)"
    )
    $url = "https://github.com/$Owner/$Project/archive/$Branch.zip"
    $output = Join-Path $DownloadPath "$($Project)-$($Branch)_$(Get-Date -Format yyyyMMdd_HHmm).zip"
    $wc = New-Object System.Net.WebClient;
    $wc.DownloadFile($url, $output)
    Expand-Archive -Path $output -DestinationPath $DownloadPath -Force
    #[version]$convertedVersion = [regex]::matches($Version, "\s*ModuleVersion\s=\s'(\d*.\d*.\d*)'\s*").groups[1].value
}#>