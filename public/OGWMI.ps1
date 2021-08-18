#$NameSpace = "Clarivate"

function New-OGWMINameSpace {
    param(
        [parameter(Mandatory=$true, HelpMessage = "The new Namespace name to create in ROOT")]
        [string]$Name,
        [parameter(Mandatory=$false, HelpMessage = "The Machine to create the namespace on. Default is local machine")]
        [string]$Machine = ".",
        [parameter(Mandatory=$false, HelpMessage = "Writes to CLI details of tasks")]
        [switch]$VerboseOutput
    )
    #Check for Namespace
    try{
        [wmiclass]"\\$($Machine)\root\$($Name)" | Out-Null
        if ($VerboseOutput){
            Write-Host "Failed - WMI Namespace found with name: $($Name)"
        }
        return $false
    }
    #Create the NameSpace
    catch{ 
        $ns=[wmiclass]"\\$($Machine)\root:__namespace"
        $CLVNamepace = $ns.CreateInstance()
        $CLVNamepace.Name = "$($Name)"
        $CLVNamepace.Put() | Out-Null
        $objNewNameSpace = [wmiclass]"\\$($Machine)\root\$($Name)"
        if ($VerboseOutput){
            Write-Host "Success - created WMI Namespace with name: $($Name)"
        }
        return $objNewNameSpace,$true
    }
}
#New-OGWMINameSpace -Name $NameSpace -VerboseOutput

function Remove-OGWMINameSpace  {
    param(
        [parameter(Mandatory=$true, HelpMessage = "The Namespace's name to be removed from ROOT")]
        [string]$Name,
        [parameter(Mandatory=$false, HelpMessage = "The Machine to remove the namespace from. Default is local machine")]
        [string]$Machine = "$($ENV:COMPUTERNAME)",
        [parameter(Mandatory=$false, HelpMessage = "Writes to CLI details of tasks")]
        [switch]$VerboseOutput
    )
    #Check for Namespace
    try{
        $WmiNamespace = Get-WmiObject -query "Select * From __Namespace Where Name='$($Name)'" -Namespace "root" -ComputerName "$($Machine)"
        if ($WmiNamespace){
            $WmiNamespace | Remove-WmiObject
            if ($VerboseOutput){
                Write-Host "Success - Removed WMI Namespace with name: $($Name)"
            }
            return $true
        }
        Else{
            if ($VerboseOutput){
                Write-Host "NO WMI Namespace found with name: $($Name)"
            }
            return $false
        }
    }
    #Create the NameSpace
    catch [System.Exception]{ 
        if ($VerboseOutput){
            Write-Host "Failed - Removed WMI Namespace with name: $($Name)"
            Write-Host "Error message: $($_.Exception.Message)"
        }
        return $false
    }
}

#Remove-OGWMINameSpace -Name $NameSpace -VerboseOutput


# $New_Classes=@"
# {  
#     "Classes":  [
#         {
#             "Class_Name": "CLV_LocalAdmin",
#             "Class_NameSpace": "root\\Clarivate",  
#             "Class_Properties": [  
#                 { 
#                     "Name": "UserName", 
#                     "Type": "String",
#                     "Key": "true",
#                     "Read": "true"
#                 },
#                 { 
#                     "Name": "Elevation_TimeStamp", 
#                     "Type": "DateTime",
#                     "Key": "false",
#                     "Read": "True"
#                 },
#                 { 
#                     "Name": "ElevationRemoval_TimeStamp", 
#                     "Type": "DateTime",
#                     "Key": "false",
#                     "Read": "True"
#                 },
#                 { 
#                     "Name": "Elevation_Option", 
#                     "Type": "String",
#                     "Key": "false",
#                     "Read": "True"
#                 }
#             ]
#         },
#         {
#             "Class_Name": "CLV_LocalAdmin2",
#             "Class_NameSpace": "root\\Clarivate",  
#             "Class_Properties": [  
#                 { 
#                     "Name": "UserName", 
#                     "Type": "String",
#                     "Key": "true",
#                     "Read": "true"
#                 },
#                 { 
#                     "Name": "Elevation_TimeStamp", 
#                     "Type": "DateTime",
#                     "Key": "false",
#                     "Read": "True"
#                 },
#                 { 
#                     "Name": "ElevationRemoval_TimeStamp", 
#                     "Type": "DateTime",
#                     "Key": "false",
#                     "Read": "True"
#                 },
#                 { 
#                     "Name": "Elevation_Option", 
#                     "Type": "String",
#                     "Key": "false",
#                     "Read": "True"
#                 }
#             ]
#         }
#     ]
# }
# "@
function New-OGWMIClass {
    param(
        [parameter(Mandatory=$true, HelpMessage = "The JSON of the class(s) to create")]
        [string]$Class_JSON,
        [parameter(Mandatory=$false, HelpMessage = "The Machine to create the class(s) on. Default is local machine")]
        [string]$Machine = "$($ENV:COMPUTERNAME)",
        [parameter(Mandatory=$false, HelpMessage = "Writes to CLI details of tasks")]
        [switch]$VerboseOutput
    )
    #Test JSON input and break if not correct.
    try {
        $Class_JSON_Converted = ConvertFrom-Json $Class_JSON -ErrorAction Stop #| Out-Null
    } 
    catch {
        Write-Host "Not valid JSON, please check your input."
        break;
    }
    $Valid_Classes = New-Object System.Collections.Generic.List[System.Object]
    $Valid_Classes_Created = New-Object System.Collections.Generic.List[System.Object]
    $Valid_Classes_Failed = New-Object System.Collections.Generic.List[System.Object]
    foreach ($class in $Class_JSON_Converted.Classes){
        try{
            $NameSpace_Classes = Get-WmiObject -Namespace "$($class.Class_NameSpace)" -ComputerName "$($Machine)" -List -ErrorAction Stop
            if ($class.Class_Name -in $NameSpace_Classes.Name){
                Write-Host "Class: '$($class.Class_Name)' already exists cannot create it."
            }
            Else{
                $Valid_Classes.Add($class)
            }
        }
        catch{
            Write-Host "No NameSpace found at: '$($class.Class_NameSpace)'"
        }
    }
    if ($Valid_Classes){
        Foreach ($v_class in $Valid_Classes){
            $v_class
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
            }
            catch{
                Write-Host "Failed creating class: '$($v_class.Class_Name)' in Namespace: '$($v_class.Class_NameSpace)'"
                $Valid_Classes_Failed.Add($v_class)
            }
        }
        if ($Valid_Classes.Count -eq $Valid_Classes_Created.Count){
            return $true
        }
        else{
            if ($VerboseOutput){
                Write-Host "Failed to create class(s):"
                $Valid_Classes_Failed
            }
            return $false
        }
    }
    Else{
        Write-Host "No Valid classes found."
        return $false
    }
}

#New-WMI_Class -Class_JSON $New_Classes -VerboseOutput


function Remove-OGWMIClass {
    param(
        [parameter(Mandatory=$true, HelpMessage = "The name of the class to delete.")]
        [string]$Class_Name,
        [parameter(Mandatory=$true, HelpMessage = "The name of the class to delete.")]
        [string]$Class_NameSpace,
        [parameter(Mandatory=$false, HelpMessage = "The Machine to delete the class from. Default is local machine")]
        [string]$Machine = ".",
        [parameter(Mandatory=$false, HelpMessage = "Writes to CLI details of tasks")]
        [switch]$VerboseOutput
    )
    try{
        $objClass=[wmiclass]"\\$($Machine)\$($Class_NameSpace):$($Class_Name)"
        $objClass.Delete()
        if ($VerboseOutput){
            Write-Host "Success removing class: '$($Class_Name)' from namespace: '\\$($Machine)\$($Class_NameSpace)'"
        }
        return $true
    }
    catch{
        if ($VerboseOutput){
            Write-Host "FAILED removing class: '$($Class_Name)' from namespace: '\\$($Machine)\$($Class_NameSpace)'"
            Write-Host "Error message: $($_.Exception.Message)"
        }
        return $false
    }
}

#Remove-OGWMIClass -Class_Name "CLV_LocalAdmin" -Class_NameSpace 'root\Clarivate'


function New-OGWMIInstance {
    param(
        [parameter(Mandatory=$true, HelpMessage = "The name of the class to delete.")]
        [string]$Class_Name,
        [parameter(Mandatory=$true, HelpMessage = "The name of the class to delete.")]
        [string]$Class_NameSpace,
        [parameter(Mandatory=$false, HelpMessage = "The Machine to delete the class from. Default is local machine")]
        [string]$Machine = ".",
        [parameter(Mandatory=$false, HelpMessage = "Writes to CLI details of tasks")]
        [switch]$VerboseOutput
    )
    try{
        $objClass=[wmiclass]"\\$($Machine)\$($Class_NameSpace):$($Class_Name)"
        $objClass.Delete()
        if ($VerboseOutput){
            Write-Host "Success removing class: '$($Class_Name)' from namespace: '\\$($Machine)\$($Class_NameSpace)'"
        }
        return $true
    }
    catch{
        if ($VerboseOutput){
            Write-Host "FAILED removing class: '$($Class_Name)' from namespace: '\\$($Machine)\$($Class_NameSpace)'"
            Write-Host "Error message: $($_.Exception.Message)"
        }
        return $false
    }
}

# $proplist = @{		
#     UserName    = "int\kbaker"
#     Elevation_TimeStamp  = $TimeStamp
#     ElevationRemoval_TimeStamp  = $TimeStamp
#     Elevation_Option  = "2h"
# }
#New-CimInstance -ClassName CLV_LocalAdmin -Namespace root\Clarivate -Property $proplist



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
		New-CimInstance -ClassName CLV_LocalAdmin -Namespace root\Clarivate -Property $proplist
	}
}

Get-WmiObject -Namespace root\Clarivate -Class CLV_LocalAdmin


$CLV.CimClassProperties


$objJSON = ConvertFrom-Json $Class
$objJSON.Classes


#Create the new class
$objNewClass= New-Object System.Management.ManagementClass ("root\Clarivate", [String]::Empty, $null); 
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
$objClass=[wmiclass]'\\.\root\Clarivate':CLV_LocalAdmin

#Delete a class
$objClass.Delete()
#>