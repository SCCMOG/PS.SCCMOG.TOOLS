##################################################################################################################################
#  Report Region
##################################################################################################################################

<#
.SYNOPSIS
    Get all updates installed withim N days

.DESCRIPTION
    Get all updates installed withim N days

.PARAMETER InstalledWithinNdays
    Installed withim N days

.EXAMPLE
    PS C:\> Get-OGWuaHistory -InstalledWithinNdays 1
    Gets all updates installed within the last 1 day:

.NOTES
    Name:       Get-OGWuaHistory       
	Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-08-17
    Updated:    -
    
    Version history:
    1.0.0 - 2021-08-17 Script created
#>
function Get-OGWuaHistory {
    param( [Parameter(Mandatory = $true)]
        [int] $InstalledWithinNdays
    )
    function convertWuaResultCodeToName {
        param( [Parameter(Mandatory = $true)]
            [int] $ResultCode
        )
        $Result = $ResultCode
        switch ($ResultCode) {
            2 {
                $Result = "Succeeded"
            }
            3 {
                $Result = "Succeeded With Errors"
            }
            4 {
                $Result = "Failed"
            }
        }
        return $Result
    }
    # Get a WUA Session
    $session = (New-Object -ComObject 'Microsoft.Update.Session')
    # Query the latest 1000 History starting with the first recordp
    $history = $session.QueryHistory("", 0, 50) | 
    ForEach-Object {
        $Result = convertWuaResultCodeToName -ResultCode $_.ResultCode
        # Make the properties hidden in com properties visible.
        $_ | Add-Member -MemberType NoteProperty -Value $Result -Name Result
        $Product = $_.Categories | Where-Object { $_.Type -eq 'Product' } | Select-Object -First 1 -ExpandProperty Name
        $_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.UpdateId -Name UpdateId
        $_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.RevisionNumber -Name RevisionNumber
        $_ | Add-Member -MemberType NoteProperty -Value $Product -Name Product -PassThru
        Write-Output $_
    }
    #Remove null records and only return the fields we want
    $history = $history | Where-Object { ![String]::IsNullOrWhiteSpace($_.title) } | Where-Object { $_.Date -ge (Get-Date).AddDays(-$InstalledWithin) } | Select-Object Result, Date, Title, SupportUrl, Product, UpdateId, RevisionNumber
    $history = $history | Sort-Object -Property Date -Unique
    return $history
}

##################################################################################################################################
# End Report Region
##################################################################################################################################

#Get-ChildItem function: | Where-Object { ($currentFunctions -notcontains $_)-and($_.Name -like "*-OG*") } | Select-Object -ExpandProperty name
$Export = @(
    "Get-OGWuaHistory"
)

foreach ($module in $Export){
    Export-ModuleMember $module
}