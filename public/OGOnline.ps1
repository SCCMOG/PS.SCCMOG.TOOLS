
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
Downlaod the sysinternals Handle Application

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
        Remove-Item -Path $Output_Path -Recurse -Force -ErrorAction SilentlyContinue
        $null = New-Item -ItemType Directory -Path $Output_Path -Force -ErrorAction Stop
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

#Get-ChildItem function: | Where-Object { ($currentFunctions -notcontains $_)-and($_.Name -like "*-OG*") } | Select-Object -ExpandProperty name
$Export = @(
    "Get-OGRecursiveAADGroupMemberUsers",
    "Get-OGHandleApp"
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