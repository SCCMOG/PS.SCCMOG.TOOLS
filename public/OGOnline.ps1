
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

.PARAMETER warrantyPeriod
    Dell Warranty period in years if only Ship date is listed when Dell API Queried.
    Default 4

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
    1.1.0 - 2024-05-24 Added warranty period for devices that only list ship date in Dell DB
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
        $warrantyPeriod = 4,
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
                'client'       = "$($Client)"
            }
            Write-OGLogEntry "[$($objWarranty.Keys.ForEach({"$_`: $($objWarranty.$_)"}) -join '][')]"
            return $objWarranty
        }
        elseif ($objResult.shipDate) {
            Write-OGLogEntry "Success retrieving Warranty data from $($vendor) for machine [Serial: $($serialNumber)][APIUri: $($dellAPIUri)]"
            $objWarranty = [System.Collections.IDictionary]@{
                'serial'       = $serialNumber
                'serviceLevel' = $objResult.countryCode
                'startDate'    = ([datetime](($objResult.shipDate | sort-object -Descending | select-object -last 1) -split 'T')[0]).ToString("yyyy-MM-dd")
                'endDate'      = ([datetime](($objResult.shipDate | sort-object -Descending | select-object -last 1) -split 'T')[0]).AddYears($warrantyPeriod).ToString("yyyy-MM-dd")
                'vendor'       = "$($vendor)"
                'client'       = "$($Client)"
            }
            Write-OGLogEntry "[$($objWarranty.Keys.ForEach({"$_`: $($objWarranty.$_)"}) -join '][')]"
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
                'client'       = "$($Client)"
            }
            Write-OGLogEntry "[$($objWarranty.Keys.ForEach({"$_`: $($objWarranty.$_)"}) -join '][')]"
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

<#
.SYNOPSIS
    Get Warranty data for a HP machine

.DESCRIPTION
    Get Warranty data for a HP machine and return it as a hash table

.PARAMETER serialNumber
    Serial number of machine

.PARAMETER HPAPIKey
    API Key provided by HP Account Manager and https://developers.hp.com/hp-warranty-api

.PARAMETER HPAPISecret
    API Secret provided by HP Account Manager and https://developers.hp.com/hp-warranty-api

.PARAMETER Client
    Org Name - Default SCCMOG

.EXAMPLE
    Get-OGHPWarranty -serialNumber $serialNumber -HPAPIKey $HPAPIKey -HPAPISecret $HPAPISecret
    Returns the warranty data for the serial number provided as a hash table

.EXAMPLE
    Get-OGHPWarranty -serialNumber $serialNumber -HPAPIKey $HPAPIKey -HPAPISecret $HPAPISecret -Client YourCompany
    Returns the warranty data for the serial number provided as a hash table and also adds your Organisation name.

.NOTES
    Name:       Get-OGHPWarranty
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2023-11-27
    Updated:    -

    Version history:
    1.0.0 - 2023-11-27 Function Created
#>
function Get-OGHPWarranty {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $serialNumber, 
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $HPAPIKey,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $HPAPISecret,
        [Parameter(Mandatory = $false)]
        $Client = "SCCMOG"
    )
    #region Constants
    $vendor = "HP"
    #credentials
    $b64EncodedCred = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($HPAPIKey):$($HPAPISecret)"))
    #token retrieval
    $tokenURI = "https://warranty.api.hp.com/oauth/v1/token"
    $tokenHeaders = @{
        accept        = "application/json"
        authorization = "Basic $b64EncodedCred"
    }
    $tokenBody = "grant_type=client_credentials"
    ##batch job
    $queryURI = "https://warranty.api.hp.com/productwarranty/v2/jobs"
    $queryHeaders = @{}
    $queryHeaders["accept"] = "application/json"
    $queryHeaders["Authorization"] = ""
    $queryBody = "[{`"sn`":`"$($serialNumber)`"}]"

    #region retrieve token
    try {
        Write-OGLogEntry "Attempting to retrieve HP access token"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $authkeyResponse = Invoke-WebRequest -UseBasicParsing -Method POST -Uri $tokenURI -Headers $tokenHeaders -Body $tokenBody -ContentType application/x-www-form-urlencoded
        $authkey = ($authkeyResponse | ConvertFrom-Json | Select-Object -Property "access_token").access_token
        $queryHeaders["Authorization"] = "Bearer $($authkey)"
        Write-OGLogEntry "Success retrieve HP access token."
    }
    catch [System.Exception] {
        Write-OGLogEntry "Failed retrieve HP access token. Error: $($_.Exception.Message)"
        return $false
    }
    #endRegion retrieve token

    #region Create batch job
    try {
        Write-OGLogEntry "Creating new batch job to retrieve warranty data. [serialNumer: $($serialNumber)][queryURI: $($queryURI)][queryBody: $($queryBody)]"
        $queryResponse = Invoke-WebRequest -UseBasicParsing -Method POST -Uri $queryURI -Headers $queryHeaders -Body $queryBody -ContentType application/json
        Write-OGLogEntry "Getting details of JOB from response."
        $jobId = ($queryResponse | ConvertFrom-Json | Select-Object -Property "jobId").jobId
        $estimatedTime = ($queryResponse | ConvertFrom-Json | Select-Object -Property "estimatedTime").estimatedTime
        if (!($jobId)) {
            Write-OGLogEntry "Failed creating Job. Exiting"
            return $false
        }
        Write-OGLogEntry "Batch job created successfully [jobID: $($jobId)][estimatedTime: $($estimatedTime)s]"
    }
    catch {
        Write-OGLogEntry "Failed creating Batch job. Error: $($_.Exception.Message)"
        return $false
    }
    #endRegion Create batch job

    #region Check status of Job
    try { 
        $JobStatusURI = $queryURI + "/" + $jobId
        $JobResultsURI = $queryURI + "/" + $jobId + "/results"
        Write-OGLogEntry "[JobStatusURI: $($JobStatusURI)]"
        Write-OGLogEntry "[JobResultsURI: $($JobResultsURI)]"
        Write-OGLogEntry "Waiting $($estimatedTime) seconds for job to complete."
        Start-Sleep($estimatedTime)
        Write-OGLogEntry "Checking if job has completed. [jobID: $($jobID)]"
        $timeOutCount = 0
        $maxTimeOutCount = 10
        $jobCheckWait = 30
        $JobStatus = Invoke-WebRequest -UseBasicParsing -Method GET -Uri $JobStatusURI -Headers $queryHeaders | ConvertFrom-Json
        #Write-OGLogEntry "Starting while loop to intermittently check the status of the job."
        while (($Jobstatus.status -eq "in progress") -and ($timeOutCount -ne $maxTimeOutCount)) {
            Write-OGLogEntry "Job not complete. Estimated time in seconds to completion: $($JobStatus.estimatedTime)"
            Write-OGLogEntry "Next job check in $($jobCheckWait) seconds. $($maxTimeOutCount - $count) checks remaining,...\n"
            Start-Sleep $jobCheckWait
            $JobStatus = Invoke-WebRequest -UseBasicParsing -Method GET -Uri $JobStatusURI -Headers $queryHeaders | ConvertFrom-Json
            $timeOutCount++
        }
        if ($JobStatus.status -eq "completed") {
            Write-OGLogEntry "Job status has been completed. [JobStatus: $($JobStatus.status)][JobStatusURI: $($JobStatusURI)]"
        }
        elseif ($timeOutCount -eq $maxTimeOutCount) {
            Write-OGLogEntry "maxTimeOutCount has been reached. [maxTimeOutCount: $($maxTimeOutCount)]" -logtype Error
            return $false
        }
        else {
            Write-OGLogEntry "The Job has failed to complete. [Status: $JobStatus][jobID: $jobId]" -logtype Error
            return $false
        }
    }
    catch [System.Exception] {
        Write-OGLogEntry "The Job has failed to complete. [jobID: $jobId]. Error: $($_.Exception.Message)" -logtype Error
        return $false
    }
    #endRegion Check status of Job

    #region Retrieve Job results
    try {
        Write-OGLogEntry "Attempting to retrieve Warranty Job results for machine [Serial: $($serialNumber)][JobStatusURI: $($JobResultsURI)]"
        $JobResults = Invoke-WebRequest -UseBasicParsing -Method GET -Uri $JobResultsURI -Headers $queryHeaders
        Write-OGLogEntry "Success retrieving Warranty Job results for machine [Serial: $($serialNumber)][JobStatusURI: $($JobResultsURI)]"
    }
    catch {
        Write-OGLogEntry "Failed retrieving Warranty Job results for machine [Serial: $($serialNumber)][JobStatusURI: $($JobResultsURI)]. Error: $($_.Exception.Message)"  -logtype Error
        return $false
    }
    #endRegion Retrieve Job results

    #region Parse and return Job Results
    try {
        Write-OGLogEntry "Parsing Warranty data from retrived results. Raw data: $($JobResults.Content)"
        $rawWarrantyResult = $JobResults.Content | ConvertFrom-Json
        Write-OGLogEntry "Looking for [offerProductIdentifier -eq HA152AW] or [offerDescription -like *HW Maintenance*]"
        $objRawHWWarranty = $rawWarrantyResult.offers | Where-Object { (($_.offerProductIdentifier -eq "HA152AW") -or ($_.offerDescription -like "*HW Maintenance*")) }
        if ($objRawHWWarranty) {
            Write-OGLogEntry "Success parsing Warranty data from $($vendor) for machine [Serial: $($serialNumber)]"  
            $objWarranty = [System.Collections.IDictionary]@{
                'serial'       = $serialNumber
                'serviceLevel' = "$($objRawHWWarranty.offerDescription),offerProductIdentifier: $($objRawHWWarranty.offerProductIdentifier),serviceObligationIdentifier: $($objRawHWWarranty.serviceObligationIdentifier)"
                'startDate'    = $($objRawHWWarranty.serviceObligationLineItemStartDate)
                'endDate'      = $($objRawHWWarranty.serviceObligationLineItemEndDate)
                'vendor'       = "$($vendor)"
                'client'       = "$($Client)"
            }
            Write-OGLogEntry "[$($objWarranty.Keys.ForEach({"$_`: $($objWarranty.$_)"}) -join '][')]"
            return $objWarranty
        }
        else {
            Write-OGLogEntry "Failed parsing Warranty data from retrived results. Did not find [offerProductIdentifier -eq HA152AW] or [offerDescription -like *HW Maintenance*] in Raw data" -logtype Error
            Write-OGLogEntry "Raw Data: $($JobResults.Content)"
            return $false
        }
    }
    catch [System.Exception] {
        Write-OGLogEntry "Failed parsing Warranty data from retrived results. Error: $($_.Exception.Message)" -logtype Error
        return $false
    }
    #endRegion Parse and return Job Results
}


#Get-ChildItem function: | Where-Object { ($currentFunctions -notcontains $_)-and($_.Name -like "*-OG*") } | Select-Object -ExpandProperty name
$Export = @(
    "Get-OGRecursiveAADGroupMemberUsers",
    "Get-OGHandleApp",
    "Get-OGDellWarranty",
    "Get-OGLenovoWarranty",
    "Get-OGHPWarranty"
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
