
<#
.SYNOPSIS
    Creates a New WMI Namespace
.DESCRIPTION
    This function checks for and if not found creates a new WMI namespace.
.EXAMPLE
    PS C:\> New-OGWMINameSpace -Name "SCCMOG" -VerboseOutput
    Created the Namespace SCCMOG in ROOT
.PARAMETER Name
    Name of new namespace 
.PARAMETER Machine
    Machine to create new namespace on. Default is local.
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    Name:       New-OGWMINameSpace
    Author:     Richie Schuster - SCCMOG.com
    github:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-08-18
    Updated:    -

    Version history:
        1.0.0 - 2021-08-18 Function created
#>
function New-OGWMINameSpace {
    param(
        [parameter(Mandatory=$true, HelpMessage = "The new Namespace name to create in ROOT")]
        [string]$Name,
        [parameter(Mandatory=$false, HelpMessage = "The Machine to create the namespace on. Default is local machine")]
        [string]$Machine = "."
    )
    #Check for Namespace
    try{
        [wmiclass]"\\$($Machine)\root\$($Name)" | Out-Null
        Write-OGLogEntry "Failed - WMI Namespace found with name: $($Name)" -logtype Error
        throw "Failed - WMI Namespace found with name: $($Name)"
    }
    #Create the NameSpace
    catch{ 
        $ns=[wmiclass]"\\$($Machine)\root:__namespace"
        $CLVNamepace = $ns.CreateInstance()
        $CLVNamepace.Name = "$($Name)"
        $CLVNamepace.Put() | Out-Null
        $objNewNameSpace = [wmiclass]"\\$($Machine)\root\$($Name)"
        Write-OGLogEntry "Success - created WMI Namespace with name: $($Name)"
        return $objNewNameSpace
    }
}

<#
.SYNOPSIS
    Removes a WMI namespace
.DESCRIPTION
    Long description
.EXAMPLE
    PS C:\> Remove-OGWMINameSpace -Name "SCCMOG" -VerboseOutput
    Removes the namespace SCCMOG from ROOT
.PARAMETER Name
    Name of namespace to remove from root

.PARAMETER Machine
    Machine to remove namespace from. Default is local.

.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
       Name:       Remove-OGWMINameSpace
       Author:     Richie Schuster - SCCMOG.com
       Website:    https://www.sccmog.com
       Contact:    @RichieJSY
       Created:    2021-08-18
       Updated:    -

       Version history:
            1.0.0 - 2021-08-18 Function created
#>
function Remove-OGWMINameSpace  {
    param(
        [parameter(Mandatory=$true, HelpMessage = "The Namespace's name to be removed from ROOT")]
        [string]$Name,
        [parameter(Mandatory=$false, HelpMessage = "The Machine to remove the namespace from. Default is local machine")]
        [string]$Machine = "$($ENV:COMPUTERNAME)"
    )
    #Check for Namespace
    try{
        $WmiNamespace = Get-WmiObject -query "Select * From __Namespace Where Name='$($Name)'" -Namespace "root" -ComputerName "$($Machine)"
        if ($WmiNamespace){
            $WmiNamespace | Remove-WmiObject
            Write-OGLogEntry -logText "Success - Removed WMI Namespace with name: $($Name)"
            return $true
        }
        Else{
            Write-OGLogEntry -logText "NO WMI Namespace found with name: $($Name)" -logtype Warning
            return $false
        }
    }
    #Create the NameSpace
    catch [System.Exception]{ 
        Write-OGLogEntry -logText "Failed - Removed WMI Namespace with name: '$($Name)'. Error message: $($_.Exception.Message)" -logtype Error
        throw "Failed - Removed WMI Namespace with name: '$($Name)'. Error message: $($_.Exception.Message)";
    }
}


<#
.SYNOPSIS
    Create WMI Class(es) in a namespace
.DESCRIPTION
    Create WMI Class(es) in a namespace from JSON. JSON example included in examples.
.EXAMPLE
    PS C:\> New-WMI_Class -Class_JSON $New_Classes
    Explanation of what the example does

    $New_Classes=@"
    {  
        "Classes":  [
            {
                "Class_Name": "SCCMOG_LocalAdmin",
                "Class_NameSpace": "root\\SCCMOG",  
                "Class_Properties": [  
                    { 
                        "Name": "UserName", 
                        "Type": "String",
                        "Key": "true",
                        "Read": "true"
                    },
                    { 
                        "Name": "Elevation_TimeStamp", 
                        "Type": "DateTime",
                        "Key": "false",
                        "Read": "True"
                    },
                    { 
                        "Name": "ElevationRemoval_TimeStamp", 
                        "Type": "DateTime",
                        "Key": "false",
                        "Read": "True"
                    },
                    { 
                        "Name": "Elevation_Option", 
                        "Type": "String",
                        "Key": "false",
                        "Read": "True"
                    }
                ]
            },
            {
                "Class_Name": "SCCMOG_LocalAdmin2",
                "Class_NameSpace": "root\\SCCMOG",  
                "Class_Properties": [  
                    { 
                        "Name": "UserName", 
                        "Type": "String",
                        "Key": "true",
                        "Read": "true"
                    },
                    { 
                        "Name": "Elevation_TimeStamp", 
                        "Type": "DateTime",
                        "Key": "false",
                        "Read": "True"
                    },
                    { 
                        "Name": "ElevationRemoval_TimeStamp", 
                        "Type": "DateTime",
                        "Key": "false",
                        "Read": "True"
                    },
                    { 
                        "Name": "Elevation_Option", 
                        "Type": "String",
                        "Key": "false",
                        "Read": "True"
                    }
                ]
            }
        ]
    }
    "@

.PARAMETER Class_JSON
    The JSON of the Class(es) to create. Example-> PS C:> Get-Help New-OGWMIClass -examples.

.PARAMETER Machine
    The machine to create the Class(es) on.

.PARAMETER Log
    Log output using Write-OGLogEntry

.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    Name:       New-OGWMIClass
    Author:     Richie Schuster - SCCMOG.com
    github:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-08-18
    Updated:    -

    Version history:
        1.0.0 - 2021-08-18 Function created
#>
function New-OGWMIClass {
    param(
        [parameter(Mandatory=$true, HelpMessage = "The JSON of the class(s) to create")]
        [string]$Class_JSON,
        [parameter(Mandatory=$false, HelpMessage = "The Machine to create the class(s) on. Default is local machine")]
        [string]$Machine = "$($ENV:COMPUTERNAME)",
        [parameter(Mandatory=$false, HelpMessage = "Writes to CLI details of tasks")]
        [switch]$Log
    )
    #Test JSON input and break if not correct.
    try {
        $Class_JSON_Converted = ConvertFrom-Json $Class_JSON -ErrorAction Stop #| Out-Null
    } 
    catch {
        Write-OGLogEntry -logText "Not valid JSON, please check your input." -logtype Error
        throw "Not valid JSON, please check your input.";
    }
    $Valid_Classes = New-Object System.Collections.Generic.List[System.Object]
    $Valid_Classes_Created = New-Object System.Collections.Generic.List[System.Object]
    $Valid_Classes_Failed = New-Object System.Collections.Generic.List[System.Object]
    foreach ($class in $Class_JSON_Converted.Classes){
        try{
            $NameSpace_Classes = Get-WmiObject -Namespace "$($class.Class_NameSpace)" -ComputerName "$($Machine)" -List -ErrorAction Stop
            if ($class.Class_Name -in $NameSpace_Classes.Name){
                Write-OGLogEntry -logText "Class: '$($class.Class_Name)' already exists cannot create it." -logtype Error
            }
            Else{
                $Valid_Classes.Add($class)
            }
        }
        catch{
            Write-OGLogEntry -logText "No NameSpace found at: '$($class.Class_NameSpace)'" -logtype Error
        }
    }
    if ($Valid_Classes){
        Foreach ($v_class in $Valid_Classes){
            try{
                $objNewClass= New-Object System.Management.ManagementClass ("$($v_class.Class_NameSpace)", [String]::Empty, $null); 
                $objNewClass["__CLASS"]="$($v_class.Class_Name)";
                foreach ($property in $v_class.Class_Properties){
                    $objNewClass.Properties.Add("$($property.Name)", [System.Management.CimType]::$($Property.Type), $false)
                    if ($property.Key -eq "true"){
                        $objNewClass.Properties["$($property.Name)"].Qualifiers.Add('key', $true)
                    }
                    if ($property.Read -eq "true"){
                        $objNewClass.Properties["$($property.Name)"].Qualifiers.Add('read', $true)
                    }
                }
                $objNewClass.Put()
                $Valid_Classes_Created.Add($v_class)
                Write-OGLogEntry -logText "Success creating class: '$($v_class.Class_Name)' in Namespace: '$($v_class.Class_NameSpace)"
            }
            catch{
                Write-OGLogEntry -logText "Failed creating class: '$($v_class.Class_Name)' in Namespace: '$($v_class.Class_NameSpace)'" -logtype Error
                $Valid_Classes_Failed.Add($v_class)
            }
        }
        if ($Valid_Classes.Count -eq $Valid_Classes_Created.Count){
            return $true
        }
        else{
            Write-OGLogEntry -logText "Failed to create class(s):" -logtype Error
            Write-OGLogEntry -logText "$Valid_Classes_Failed"
            return $false
        }
    }
    Else{
        Write-OGLogEntry -logText "No Valid classes found." -logtype Error
        throw "No Valid classes found."
    }
}

<#
.SYNOPSIS
    Remove a WMI class
.DESCRIPTION
    This function will remove a WMI class from the specified instance.
.EXAMPLE
    PS C:\> Remove-OGWMIClass -Class_Name "SCCMOG_LocalAdmin" -Class_NameSpace 'SCCMOG'
    Removes the SCCMOG_LocalAdmin class from WMI name space SCCMOG.
.PARAMETER Class_Name
    Class to be removed

.PARAMETER Class_NameSpace
    Namespace class is a child of.

.PARAMETER Machine
    Machine to remove class from. Default is local.
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    Name:       Remove-OGWMIClass
    Author:     Richie Schuster - SCCMOG.com
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-08-18
    Updated:    -

    Version history:
        1.0.0 - 2021-08-18 Function created
#>
function Remove-OGWMIClass {
    param(
        [parameter(Mandatory=$true)]
        [string]$Class_Name,
        [parameter(Mandatory=$true)]
        [string]$Class_NameSpace,
        [parameter(Mandatory=$false, HelpMessage = "The Machine to delete the class from. Default is local machine")]
        [string]$Machine = "."
    )
    try{
        $objClass=[wmiclass]"\\$($Machine)\ROOT\$($Class_NameSpace):$($Class_Name)"
        $objClass.Delete()
        Write-OGLogEntry -logText "Success removing class: '$($Class_Name)' from namespace: '\\$($Machine)\$($Class_NameSpace)'"
        return $true
    }
    catch{
        $message = "FAILED removing class: '$($Class_Name)' from namespace: '\\$($Machine)\$($Class_NameSpace)'. Error message: $($_.Exception.Message)"
        Write-OGLogEntry -logText $message -logType Error
        throw $message;
    }
}

<#
.SYNOPSIS
    Gets for a WMI class
.DESCRIPTION
    Gets for a WMI class from a namespace in ROOT.
    Will then return WMI Class Object or if not found $false 
.EXAMPLE
    PS C:\> Get-OGWMIClass -Class_Name "SCCMOG_LocalAdmin" -Class_NameSpace 'SCCMOG'
    Explanation of what the example does
.PARAMETER Class_Name
    Class to check for
.PARAMETER Class_NameSpace
    Namespace to search for class.
.PARAMETER Machine
    Machine to remove class from. Default is local.
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    Name:      Get-OGWMIClass
    Author:    Richie Schuster - SCCMOG.com
    Website:   https://www.sccmog.com
    Contact:   @RichieJSY
    Created:   2021-08-18
    Updated:   -

    Version history:
        1.0.0 - 2021-08-18 Function created
#>
function Get-OGWMIClass () {
    param(
        [parameter(Mandatory=$true)]
        [string]$Class_Name,
        [parameter(Mandatory=$true)]
        [string]$Class_NameSpace,
        [parameter(Mandatory=$false)]
        [string]$Machine = "."
    )
    $MachineRoot = "\\$($Machine)\ROOT"
    try{
        $objClass=[wmiclass]"$($MachineRoot)\$($Class_NameSpace):$($Class_Name)"
        Write-OGLogEntry -logText "Success class: '$($Class_Name)' exists in namespace: '$($MachineRoot)\ROOT\$($Class_NameSpace)'"
        return $objClass
    }
    catch{
        Write-OGLogEntry -logText "Class: '$($Class_Name)' does NOT exist in namespace: '$($MachineRoot)\ROOT\$($Class_NameSpace)'" -logType Warning
        return $false
    }
}

<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.EXAMPLE
    PS C:\> New-OGWMIInstance -Class_Name "OG_LocalAdmin" -Class_NameSpace "SCCMOG" -Instance $objNewInstance
    Created a new instance from the Hashtable below on the local machine.
        $objNewInstance = @{		
        UserName    = "sccmog\kbaker"
        Elevation_TimeStamp  = $TimeStamp
        ElevationRemoval_TimeStamp  = $TimeStamp
        Elevation_Option  = "2h"
        }
.EXAMPLE
    PS C:\> New-OGWMIInstance -Class_Name "OG_LocalAdmin" -Class_NameSpace "SCCMOG" -Instance $objNewInstance -Machine "TESTMACHINE"
    Created a new instance from the Hashtable below on the local machine.
        $objNewInstance = @{		
            UserName    = "sccmog\kbaker"
            Elevation_TimeStamp  = $TimeStamp
            ElevationRemoval_TimeStamp  = $TimeStamp
            Elevation_Option  = "2h"
        }
.PARAMETER Class_Name
    The name of the Class to that the Instance will be reated in.

.PARAMETER Class_NameSpace
    The Namespace the Class is a member of.

.PARAMETER Instance
    The Hashtable of the Instance data. see -Example for example.
.PARAMETER Machine
    The machine to create the new instance. Default is local.
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    Name:       New-OGWMIInstance
    Author:     Richie Schuster - SCCMOG.com
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-08-18
    Updated:    -

    Version history:
        1.0.0 - 2021-08-18 Function created
#>
function New-OGWMIInstance {
    param(
        [parameter(Mandatory=$true, HelpMessage = "The name of the Class to that the Instance will be reated in.")]
        [string]$Class_Name,
        [parameter(Mandatory=$true, HelpMessage = "The Namespace the Class is a member of.")]
        [string]$Class_NameSpace,
        [parameter(Mandatory=$true, HelpMessage = "The Hashtable of the Instance data.")]
        [Hashtable]$Instance,
        [parameter(Mandatory=$false, HelpMessage = "The Machine to delete the class from. Default is local machine")]
        [string]$Machine = "."
    )
    try{
        $Class = Get-OGWMIClass -Class_Name "$($Class_Name)" -Class_NameSpace "$($Class_NameSpace)" -Machine $Machine
        if($machine -eq "."){$Machine=$env:COMPUTERNAME}
        if ($Class){
            if($machine -eq "."){$Machine=$env:COMPUTERNAME}
            $objInstance = New-CimInstance -ClassName "$($Class_Name)" -Namespace" root\$($Class_NameSpace)" -Property $Instance -ComputerName $Machine
            Write-OGLogEntry "Success creating new instance: '$($Instance.ToString())' in class: '$($Class)' Machine: '$($Machine)'"
            return $objInstance
        }
        Else{
            $message = "No Class with name: '$($Class_Name)' found in Namespace: '$($Class_NameSpace)' Machine: '$($Machine)'. Bailing out."
            Write-OGLogEntry $message -logtype Error
            throw $message;
        }
    }
    catch{
        $message = "FAILED creating new instance: '$($Instance.ToString())' in class: '$($Class)' Machine: '$($Machine)'. Error message: $($_.Exception.Message)"
        Write-OGLogEntry $message -logtype Error
        throw $message;
    }
}


#New-CimInstance -ClassName CLV_LocalAdmin -Namespace root\SCCMOG -Property $proplist

<#notes
$TimeStamp = $(Get-Date)
if($Users = Import-CSV C:\Temp\import.csv){
	foreach ($user in $Users) {
		$proplist = @{		
			UserName    = "$($user.Name)"
			Elevation_TimeStamp  = $TimeStamp
			ElevationRemoval_TimeStamp  = $TimeStamp
            Elevation_Option  = "$($user.ElevationOption)"
		}
		New-CimInstance -ClassName CLV_LocalAdmin -Namespace root\SCCMOG -Property $proplist
	}
}

Get-WmiObject -Namespace root\SCCMOG -Class CLV_LocalAdmin


$CLV.CimClassProperties


$objJSON = ConvertFrom-Json $Class
$objJSON.Classes


#Create the new class
$objNewClass= New-Object System.Management.ManagementClass ("root\SCCMOG", [String]::Empty, $null); 
$objNewClass["__CLASS"]="CLV_LocalAdmin";
$objNewClass.Properties.Add("UserName", [System.Management.CimType]::String, $false)
$objNewClass.Properties['UserName'].Qualifiers.Add('key', $true)
$objNewClass.Properties['UserName'].Qualifiers.Add('read', $true)
$objNewClass.Properties.Add("Elevation_TimeStamp", [System.Management.CimType]::DateTime, $false)
$objNewClass.Properties["Elevation_TimeStamp"].Qualifiers.Add("read", $true)
$objNewClass.Properties.Add("ElevationRemoval_TimeStamp", [System.Management.CimType]::DateTime, $false)
$objNewClass.Properties["ElevationRemoval_TimeStamp"].Qualifiers.Add("read", $true)
$objNewClass.Properties.Add("Elevation_Option", [System.Management.CimType]::String, $false)
$objNewClass.Properties["Elevation_Option"].Qualifiers.Add("read", $true)
$objNewClass.Put()

#Get the new class property to be a key
$objClass=[wmiclass]'\\.\root\SCCMOG':CLV_LocalAdmin

#Delete a class
$objClass.Delete()
#>