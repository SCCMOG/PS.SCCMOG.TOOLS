
<#
.SYNOPSIS
    Select Unique objects from an object.
.DESCRIPTION
    Many times – mainly when writing function cmdlets for other purposes – I find that I need to output all unique objects based on one or two properties but want all the objects’ properties returned.
    PowerShell’s built-in Select-Object doesn’t let me do that. Apart from enumerating and collecting all objects before outputing them to the pipeline, it only return the properties that you specified.
    To let all the objects flow through the pipeline as they are enumerating, I added my own Select-Unique cmdlet to my $profile a couple of years ago but wanted to share it now as a Gist.
    https://lifeofheath.wordpress.com/2012/08/15/a-faster-way-to-output-unique-objects-in-powershell/
.EXAMPLE
    PS C:\> Select-Unique -Property Mail -InputObject $AADGroupMembers
    Gets all unique elements from the array based off the email property of an element and returns an array of all unique elements in the array.
.EXAMPLE
    PS C:\> Select-Unique -Property Mail -InputObject $AADGroupMembers -HashTable
    Gets all unique elements from the array using the email property of an element and returns an Hashtable of all unique elements in the array, "Key" being the property(s).
.EXAMPLE
    PS C:\> Select-Unique -Property Mail -InputObject $AADGroupMembers -NoElement
    Gets all unique elements from the array based off the email property of an element and returns an array of all unique elements in the array.
.PARAMETER Property
    The properties to use to get unique results from the inputobject.

.PARAMETER InputObject
    The Inputobject to sort uniquely

.PARAMETER AsHashtable
    Return data as HashTable

.PARAMETER NoElement
    Do not include an Element
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    Name:       Select-OGUnique
    Original:   https://lifeofheath.wordpress.com/2012/08/15/a-faster-way-to-output-unique-objects-in-powershell/
    Modded:     Richie Schuster - SCCMOG.com
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2012-08-12
    Updated:    2021-08-27

    Version history:
        1.0.0 - 2012-08-12 Function created
        2.0.0 - 2021-08-27 Updated
#>
function Select-OGUnique {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string[]] $Property,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $InputObject,
        [Parameter()]
        [switch] $AsHashtable,
        [Parameter()]
        [switch] $NoElement
    )
    begin {
        $Keys = @{}
    }
    process {
        Write-OGLogEntry "Getting Unique objects from input object with current count: $($InputObject.Count)"
        $InputObject | foreach-object {
            $o = $_
            $k = $Property | foreach-object -begin {
                $s = ''
            } -process {
                # Delimit multiple properties like group-object does.
                if ( $s.Length -gt 0 ) {
                    $s += ', '
                }

                $s += $o.$_ -as [string]
            } -end {
                $s
            }

            if ( -not $Keys.ContainsKey($k) ) {
                $Keys.Add($k, $null)
                if ( -not $AsHashtable ) {
                    $o
                }
                elseif ( -not $NoElement ) {
                    $Keys[$k] = $o
                }
            }
        }
    }
    end {
        if ( $AsHashtable ) {
            $Keys
        }
        Write-OGLogEntry "InputObject Unique Count: $($Keys.Count) Property(s) used: $($Property)"
    }
}


<#
.SYNOPSIS
Converts a registry object to an Order list or ordered HashTable

.DESCRIPTION
Converts a registry object to an Order list or ordered HashTable

.PARAMETER objReg
Accepts a Powershell Registry object.

.PARAMETER AsHashtable
Return an ordered HashTable

.EXAMPLE
Convert-OGReg2PSObject -objReg $UserRegKey
Return an ordered List from registry object $UserRegKey

.EXAMPLE
Convert-OGReg2PSObject -objReg $UserRegKey -AsHashtable
Return an ordered HashTable from registry object $UserRegKey

.EXAMPLE
$UserRegKey | Convert-OGReg2PSObject 
Pipeline return an ordered List from registry object $UserRegKey

.EXAMPLE
$UserRegKey | Convert-OGReg2PSObject -AsHashtable
Pipeline return an ordered HashTable from registry object $UserRegKey

.NOTES
    Name:       Convert-OGReg2PSObject
    Original:   https://lifeofheath.wordpress.com/2012/08/15/a-faster-way-to-output-unique-objects-in-powershell/
    Modded:     Richie Schuster - SCCMOG.com
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-01-12
    Updated:    -

    Version history:
        1.0.0 - 2022-01-12 Function created
#>


function Convert-OG2PSObject{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, Position = 0,ValueFromPipeline)]
        [psobject] $objReg,
        [Parameter(Position = 1)]
        [switch] $AsHashtable,
        [Parameter(Position = 2)]
        [switch] $ExpandString
    )
    $regList= @()
    $sregList = @()
    $regHash = [ordered]@{}
    $objReg.psobject.Properties | Where-Object -Property name -notlike "ps*" | ForEach-Object {
        $value = $_.Value
        if ($ExpandString){$value = $ExecutionContext.InvokeCommand.ExpandString($value)}  
            $reg_Property = [PSCustomObject]@{
                Property = $_.Name
                Value = $value             
            }
            $regList += $reg_Property          
    }
    $sregList = $regList | Sort-object -Property Property
    if (!($AsHashtable)){
        return $sregList
    }
    else{
        $sregList | ForEach-Object {
            $regHash.Add($_.Property ,$_.Value)      
        }
        return $regHash
    }
}


function Invoke-ExpandString {
    param(
        [Parameter(Mandatory = $true, Position = 0,ValueFromPipeline)]
        [string]$string
    )
        $ExecutionContext.InvokeCommand.ExpandString($string)
        return $string
}


#Get-ChildItem function: | Where-Object { ($currentFunctions -notcontains $_)-and($_.Name -like "*-OG*") } | Select-Object -ExpandProperty name
$Export = @(
    "Select-OGUnique",
    "Convert-OG2PSObject",
    "Invoke-ExpandString"
)

foreach ($module in $Export){
    Export-ModuleMember $module
}
#>
