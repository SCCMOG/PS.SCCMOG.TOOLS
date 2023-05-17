
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
Convert JSON time stamp to Unix Timestamp

.DESCRIPTION
Convert JSON time stamp to Unix Timestamp

.PARAMETER TimeStamp
JSON TimeStamp

.EXAMPLE
$DateAdded = [Decimal] $node.date_added
ConvertTo-OGUnixTimeStamp -TimeStamp  $DateAdded

.EXAMPLE
$DateAdded = [Decimal] $node.date_added
$DateAdded | ConvertTo-OGUnixTimeStamp

.NOTES
    Name:       ConvertTo-OGUnixTimeStamp
    Author:     Richie Schuster - SCCMOG.com
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-02-09
    Updated:    

    Version history:
        1.0.0 - 2022-02-09 Function created
#>

function ConvertTo-OGUnixTimeStamp {
    param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        $TimeStamp 
    )
    if ($TimeStamp -eq 0){
        return 0
    }
    else{
        # Reference-Timestamp needed to convert Timestamps of JSON (Milliseconds / Ticks since LDAP / NT epoch 01.01.1601 00:00:00 UTC) to Unix-Timestamp (Epoch)
        $Date_LDAP_NT_EPOCH = Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0
        $date = [Decimal] $TimeStamp
        if ($date -gt 0) { 
            $date = $Date_LDAP_NT_EPOCH.AddTicks($date * 10)
            $date = $date | Get-Date -UFormat %s 
            $unixTimeStamp = [int][double]::Parse($date) - 1
            return $unixTimeStamp
        }
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
    Author:     Richie Schuster - SCCMOG.com
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

<#
.SYNOPSIS
Creates an encrypted file with a string password

.DESCRIPTION
Creates an encrypted file with a string password

.PARAMETER String
The string password you would like to encrypt

.PARAMETER OutFile
Path to spit out the encrypted file.

.PARAMETER Force
Replace out-file if found. 

.EXAMPLE
New-OGEncryptedStrFile -String "MyCrazyPassword" -OutFile "PathAndFileName\toStorePass\Encrypted"

.NOTES
    Name:       Get-OGEncryptedStrFile
    Author:     Richie Schuster - SCCMOG.com
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-01-26
    Updated:    -

    Version history:
        1.0.0 - 2022-01-26 Function created
#>
function New-OGEncryptedStrFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$String,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$OutFile,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [switch]$Force
    )
    try {
        $SecurePassword = ConvertTo-SecureString $string -AsPlainText -Force
        $Encrypted = convertfrom-securestring $SecurePassword -key (1..16)
        if ($Force){
            if (Test-OGFilePath -Path $OutFile){
                Remove-Item -Path $OutFile -Force
            }
        }
        $Encrypted | set-content $OutFile -Force
    }
    catch {
        throw "Failed creating encrypted file. Error: $_"
    }

}



<#
.SYNOPSIS
Converts a previously encrypted string in file back to clear text.

.DESCRIPTION
Converts a previously encrypted string in file back to clear text.

.PARAMETER FilePath
Path to encrypted file.

.EXAMPLE
Get-OGEncryptedStrFile -FilePath "$($scriptRoot)\NameOfFile"

.NOTES
    Name:       Get-OGEncryptedStrFile
    Author:     Richie Schuster - SCCMOG.com
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-01-26
    Updated:    -

    Version history:
        1.0.0 - 2022-01-26 Function created
#>
function Get-OGEncryptedStrFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath
    )
    if (!(Test-path $FilePath -PathType Leaf)) {
        throw "No file found at: $($FilePath)"
    }
    try {
        $SecreRet = convertto-securestring (get-content "$($FilePath)") -key (1..16)
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecreRet)
        $UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        return $UnsecurePassword
    }
    catch {
        throw "Failed getting encrypted file. Error: $_"
    }
}

<#
.SYNOPSIS
Expands a PS variable from a string.

.DESCRIPTION
Expands a PS variable from a string.

.PARAMETER string
String containing variable

.EXAMPLE
Invoke-ExpandString -string "$ENV:ComputerName"

.NOTES
    Name:       Invoke-ExpandString
    Author:     Richie Schuster - SCCMOG.com
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-01-21
    Updated:    -

    Version history:
        1.0.0 - 2022-01-21 Function created
#>
function Invoke-ExpandString {
    param(
        [Parameter(Mandatory = $true, Position = 0,ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$string
    )
        $ExecutionContext.InvokeCommand.ExpandString($string)
        return $string
}

<#
.SYNOPSIS
Correct string for XML parsing

.DESCRIPTION
Correct string for XML parsing

.PARAMETER String
String to parse

.EXAMPLE
Repair-OGXmlString -String $strTaskArgs

.NOTES
    Name:       Repair-OGXmlString
    Author:     Richie Schuster - SCCMOG.com
    Original:   https://stackoverflow.com/a/45708615
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-01-31
    Updated:    -

    Version history:
        1.0.0 - 2022-01-31 Function created
#>
function Repair-OGXmlString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0,ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$String
    )
    Write-OGLogEntry "Cleaning string for XML parsing [String: $($String)]"
    $rPattern = "[^\x09\x0A\x0D\x20-\xD7FF\xE000-\xFFFD\x10000\x10FFFF]"
    $cleaned = $String -replace $rPattern, ''
    Write-OGLogEntry "Returned parsed string [String: $($cleaned)]"
    return $cleaned
}


<#
.SYNOPSIS
Convert HEX to ASCII

.DESCRIPTION
Convert HEX to ASCII

.PARAMETER HexString
HEX as string.

.EXAMPLE
ConvertFrom-OGHexa -HexString  $NewProfileHex

.NOTES
    Name:       ConvertFrom-OGHexa
    Author:     Richie Schuster - SCCMOG.com
    Original:   https://www.reddit.com/r/PowerShell/comments/48bxto/comment/d0j14hc/?utm_source=share&utm_medium=web2x&context=3
                https://community.spiceworks.com/topic/1951587-move-ost-file-locaiton-for-existing-outlook-profiles
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-01-31
    Updated:    -

    Version history:
        1.0.0 - 2022-01-31 Function created
        2.0.0 - 2022-03-08 Convertion cmdlet changed due to output issue.
#>
function ConvertFrom-OGHexa {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [array]$HexString
    )
    Write-OGLogEntry "Attempting to convert HEX to ASCII"
    try {
        #$string = [System.Text.Encoding]::Unicode.GetString(($HexString))
        $string = ($hexstring | Where-Object { $_ -gt '0' } | ForEach-Object { [char][int]"$($_)" }) -join ''
        Write-OGLogEntry "Success converting HEX to ASCII."
        return $string
    }
    catch {
        Write-OGLogEntry "Failed converting HEX to ASCII. Error: $_"
        return $null
    }
}

#Get-ChildItem function: | Where-Object { ($currentFunctions -notcontains $_)-and($_.Name -like "*-OG*") } | Select-Object -ExpandProperty name
$Export = @(
    "Select-OGUnique",
    "Convert-OG2PSObject",
    "New-OGEncryptedStrFile",
    "Get-OGEncryptedStrFile",
    "Invoke-ExpandString",
    "Repair-OGXmlString",
    "ConvertFrom-OGHexa",
    "ConvertTo-OGUnixTimeStamp"
)

foreach ($module in $Export){
    Export-ModuleMember $module
}
#>
