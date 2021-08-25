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
}

<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.EXAMPLE
    PS C:\> Get-OGRecursiveAADGroupMemberUsers -AzureGroupName "My Azure Group Name"
    Gets all recursive members of the group name supplied.
.PARAMETER AzureGroupName
Parameter description
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
        $AzureGroupName
    )
    Begin{
        If(-not(Get-AzureADCurrentSessionInfo)){Connect-AzureAD}
    }
    Process {
        $AzureGroup = Get-AzureADGroup -SearchString "$AzureGroupName" -ErrorAction Stop
        if($AzureGroup){
            Write-Verbose -Message "Enumerating $($AzureGroup.DisplayName)"
            $Members = Get-AzureADGroupMember -ObjectId $AzureGroup.ObjectId -All $true -ErrorAction Stop
            $UserMembers = $Members | Where-Object{$_.ObjectType -eq 'User'}
            If($Members | Where-Object{$_.ObjectType -eq 'Group'}){
                $UserMembers += $Members | Where-Object{$_.ObjectType -eq 'Group'} | ForEach-Object{ Get-OGRecursiveAADGroupMemberUsers -AzureGroupName $_.DisplayName}
            }
        }
        else{
            throw "No AAD group found with name: '$($AzureGroupName)'"
        }

    }
    end {
        Return $UserMembers
    }
}


#Get-ChildItem function: | Where-Object { ($currentFunctions -notcontains $_)-and($_.Name -like "*-OG*") } | Select-Object -ExpandProperty name
$Export = @(
    "Get-OGRecursiveAADGroupMemberUsers"
)

foreach ($module in $Export){
    Export-ModuleMember $module
}
#>
