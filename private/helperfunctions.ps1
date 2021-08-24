function new-scriptFrame{
    param(
        [Parameter(Mandatory=$true)][string]$frameName,
        [Parameter(Mandatory=$true)][string]$line,
        [Parameter(Mandatory=$true)][string]$scriptName
    )
    $scriptFrame = [PSCustomObject]@{
        Name = $frameName
        Line = $line 
        ScriptName = $scriptName
    }
    return $scriptFrame
}

function getCallSequence(){
    $stack = @()
    $line = 0
    #$functionCall = @()
    $stringCallStack = ""

    #Get current call stack
    $trace = Get-PSCallStack
    $trace | ForEach-Object { if (( $_.Command -notlike "*Log-Entry*")-and($_.Command -notlike "*<ScriptBlock>*")){$stack += $_.Command}}
    $callStack = $stack[-1..-($stack.Length - 2)]
    #reverse array
    #[array]::Reverse($callStack)
    $scriptName = $callStack | Select-Object -First 1
    $stringCallStack = $callStack -join "|"
    #$stringCallStack = $callStack -join " | "
    
    
    #Obtain the details of the line in the script being executed and the function/script names
    $lineArray = $trace.ScriptLineNumber -split ' '
    $lineArray = $lineArray | Select-Object -Skip 2 | Select-Object -SkipLast 1
    if (!($null -eq $lineArray)){
        [array]::Reverse($lineArray)
        $line = $lineArray -join ":"
    }
    else{
        $lineArray = "0"
    }


    #create script function call information
    $functionCall = new-scriptFrame -frameName $stringCallStack -Line $line -scriptname $scriptName
    return $functionCall
}

function getNewFileName () {
    $tmpFile = [System.IO.Path]::GetTempFileName()
    Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
    return $tmpFile.Replace('.tmp','.log')
}

function checkDefaultLogDir(){
    try{
        if (!(Test-Path -Path "$global:PS_NEWOGLogEntry_DEFAULT_LOGDIR" -PathType Container)){
            New-Item -Path "$($ENV:ProgramData)" -Name "Logs" -ItemType Directory -Force | Out-Null 
        }
        if (Test-Path -Path "$global:PS_NEWOGLogEntry_DEFAULT_LOGDIR" -PathType Container){
            New-Item -Path "$($ENV:ProgramData)" -Name "Logs" -ItemType Directory -Force | Out-Null
            #Set Full Control for Built in Users Group
            $BuiltinUsersSID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-545'
            $BuiltinUsersGroup = $BuiltinUsersSID.Translate([System.Security.Principal.NTAccount])
            $ACL = Get-Acl "$global:PS_NEWOGLogEntry_DEFAULT_LOGDIR"
            $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$($BuiltinUsersGroup.Value)",
                                                                                            "FullControl",
                                                                                            'ContainerInherit,ObjectInherit',
                                                                                            'None',
                                                                                            "Allow")
            $ACL.SetAccessRule($AccessRule)
            $ACL | Set-Acl $global:PS_NEWOGLogEntry_DEFAULT_LOGDIR
            return $true
        }
    }
    catch{
        Write-Error "Failed configuring defualt log folder. Error: $_"
        break
    }
}

function getDefaultLogFileName () {
    $cs = getCallSequence
    $scriptName = (($cs.ScriptName).Replace(".ps1","")).ToString()
    return $scriptName
}

function getDefaultLogDetails(){
    checkDefaultLogDir
    $LogName = getDefaultLogFileName -verbose
    $defaultLogDetails = [PSCustomObject]@{
        DefaultLogFilePath = "$($global:PS_NEWOGLogEntry_DEFAULT_LOGDIR)\$($LogName).log";
        ScriptName = "$($LogName)"
    }
    return $defaultLogDetails
}

function scriptTimer(){
    param(
        [switch]$Start,
        [switch]$Stop
    )

    if($Start){
        $script:StopWatch = $null
        $script:StopWatch =  [system.diagnostics.stopwatch]::StartNew()
    }
    elseif($Stop){
        $script:StopWatch.Stop()
        $scriptRunTime = ("{0:hh\:mm\:ss\.fff}" -f $script:StopWatch.Elapsed)
        return $scriptRunTime
    }
    else{
        break
    }
}


function writeLogEntry{
    param(
        [Object[]]$objLogEntry
    )

    switch("$($objLogEntry.LogType)"){
        { @("Info", "Header","Footer") -contains $_ }{$logcolour = "White"}
        "Warning"{$logcolour = "DarkYellow"}
        "Error"{$logcolour = "Red"}
    }

    switch("$($objLogEntry.LogType)"){
        { @("Info", "Warning","Error") -contains $_ }{
            #Build standard log file entry
            $logFileEntry = "[{0,-19}][{1}][{2}][{3}][{4}] --> {5}" -f $(($objLogEntry.DateTime).ToString('yyyy-MM-dd HH:mm:ss.fff')),
                                                                        $($objLogEntry.Trace),
                                                                        $($objLogEntry.Line),
                                                                        $($objLogEntry.PID),
                                                                        $($objLogEntry.LogType),
                                                                        $($objLogEntry.LogText)
            $eLogEntry = ($objLogEntry | Format-List | Out-String)
        }
        "Header"{
            scriptTimer -Start
            $logFileEntry = "##############################[{0,-19}][{1}][{2}]##############################" -f $(($objLogEntry.DateTime).ToString('yyyy-MM-dd HH:mm:ss.fff')),
                                                                    "$(($global:PS_SCCMOG_cScriptName).ToUpper()) HAS STARTED",
                                                                    "PID: $($objLogEntry.PID)"
            $logFileEntry = $logFileEntry + "`n`r##############[{0,-19}]" -f "PATH: '$($objLogEntry.Path)'"
                                                                
            $eLogEntry = "[{0,-19}]`n`r" -f "$(($objLogEntry.Trace).ToUpper()) HAS STARTED" + ($objLogEntry | Format-List | Out-String)                                   
        }
        "Footer"{
            $Script:RunTime = scriptTimer -Stop
            #Workout Runtime
            $logFileEntry = "##############################[{0,-19}][{1}][{2}][{3}]##############################" -f $(($objLogEntry.DateTime).ToString('yyyy-MM-dd HH:mm:ss.fff')),
                                                                    "$(($global:PS_SCCMOG_cScriptName).ToUpper()) HAS COMPLETED",
                                                                    "PID: $($objLogEntry.PID)",
                                                                    "RUNTIME: $($Script:RunTime)"
            $eLogEntry = "[{0,-19}]`n`r" -f "$(($objLogEntry.Trace).ToUpper()) HAS COMPLETED - RUNTIME: $($Script:RunTime)" + ($objLogEntry | Format-List | Out-String)       
        }
    }

    
    #$global:PS_NEWOGLogEntry_DEFAULT_LOGPATH
    Write-Host $logFileentry -ForegroundColor $logcolour
    $logFileEntry | out-file -filepath $global:PS_NEWOGLogEntry_DEFAULT_LOGPATH -encoding Default -width 16384 -append
    if ($script:PS_NEWOGLogEntry_DEFAULT_LogtoEventLog){
        writeEventLog -eventLog "$($script:PS_NEWOGLogEntry_DEFAULT_EventLog)" -EventSource "$($script:PS_NEWOGLogEntry_DEFAULT_EventLogSource)" -messageType "$($objLogEntry.LogType)" -message $eLogEntry
    }
}


function getEventLog{
    param(
        [Parameter(Mandatory = $false)]
        [string]$LogName
    )
    $allEventLogs = Get-EventLog -List
    $selectEventLog = $allEventLogs | Where-Object {$_.Log -eq "$($LogName)"}
    if ($selectEventLog){
        return $selectEventLog
    }
    else{
        return $false
    }
}


function writeEventLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$eventLog,
        [Parameter(Mandatory = $true)]
        [string]$EventSource,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info","Warning","Error","Header","Footer")]
        [string]$messageType = "Info",
        [Parameter(Mandatory = $true)]
        [string]$message
    )
    switch($messageType){
        { @("Info", "Header","Footer") -contains $_ }{$sMessageType = "Information";$sMessageID = 2020;$Catagory = 1}
        "Warning"{$sMessageType = "Warning";$sMessageID = 1985;$Catagory = 2}
        "Error"{$sMessageType = "Error";$sMessageID = 5555;$Catagory = 3}
    }
    Write-EventLog -LogName "$($eventLog)" -Source "$($EventSource)" -Category $Catagory -EventId $sMessageID -Message "$($message)" -EntryType $sMessageType -RawData 10,20
}
#Remove-EventLog -LogName "Clarivate Deployment"
function newEventLog{
    param(
        [Parameter(Mandatory = $true)]
        [String]$LogName,
        [Parameter(Mandatory = $true)]
        [String[]]$SourceName
    )
    $EventSources = @()
    #Setup event sources
    $ConfigEventSource = "Configuration"
    $EventSources += $ConfigEventSource
    $SourceName | ForEach-Object {$EventSources += $_}

    #Get all current event logs and check for match
    $selectEventLog = getEventLog -LogName $LogName
    #If match then show sources available and mention new source method
    if ($selectEventLog){
        Write-Warning -Message "Event log with name: $($LogName) already found. Please add to log."
        $sources = getEventLogSource -eventLog "$($selectEventLog.Log)"
        Write-Warning -Message "Event Log: $($LogName) Sources Available: $($sources)"
    }
    Else{
        try{
            $SourceName
            New-EventLog -LogName "$($LogName)" -Source $EventSources -Verbose
        }
        catch{
            Write-Error "Failed to create the Event Log: $($LogName). $_"
        }
        try{
            writeEventLog -eventLog "$($LogName)" -EventSource "$($ConfigEventSource)" -messageType "Info" -message "Event Log: '$($LogName)' with sources: '$($EventSources)' has been created." 
        }
        catch{
            Write-Error "Failed to write to Event Source:'$($ConfigEventSource)' for event log:'$($LogName)'. $_"
        }
    }
}

function getEventLogSource{
    param(
        [Parameter(Mandatory = $true)]
        [string]$eventLog
    )  


    $selectEventLog = getEventLog -LogName $eventLog
    if ($selectEventLog){
        $Sources = (Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$($eventLog)").pschildname | Select-Object -Skip 1
        return $sources
    }else{
        Write-Error "No Event log foun with name: $($EventLog)."
    }
}


function newEventLogSource {
    param(
        [Parameter(Mandatory = $true)]
        $EventLog,
        [Parameter(Mandatory = $true)]
        $EventSource
    )
    $sources = getEventLogSource -eventLog $EventLog
    if ($sources){
        if ($EventSource -in $sources){
            Write-Error "Event source: '$($EventSource)' already present in: '$($EventLog)'. Not creating."
        }
        Else{
            [System.Diagnostics.EventLog]::CreateEventSource("$EventSource", "$EventLog")
            Write-Verbose "Success creating Event source: '$($EventSource)' in: '$($EventLog)'."
        }
    }
    Else{
        Write-Error "No Event log with name: '$($EventLog)' found to create Logsource: '$($EventSource)'"
    }
}

function initializeEventLogs{
    $elog = getEventLog -LogName "$script:PS_NEWOGLogEntry_DEFAULT_EventLog"
    if ($eLog){
        $eLogSource = getEventLogSource -eventLog "$($eLog.Log)"
        if ("$($script:PS_NEWOGLogEntry_DEFAULT_EventLogSource)" -in $eLogSource){
            Write-Verbose "Event log: '$($script:PS_NEWOGLogEntry_DEFAULT_EventLog)' already configured with Source: '$($script:PS_NEWOGLogEntry_DEFAULT_EventLogSource)'"
        }
        else{
            Write-Verbose "No eventlog source with name: '$($script:PS_NEWOGLogEntry_DEFAULT_EventLogSource)' found in event log '$($script:PS_NEWOGLogEntry_DEFAULT_EventLog)'. So it was created."
            newEventLogSource -EventLog "$($script:PS_NEWOGLogEntry_DEFAULT_EventLog)" -EventSource "$($script:PS_NEWOGLogEntry_DEFAULT_EventLogSource)"
        }
    }
    else{
        Write-Verbose "No eventlog found with name: '$($script:PS_NEWOGLogEntry_DEFAULT_EventLog)' So it will be created."
        newEventLog -LogName "$script:PS_NEWOGLogEntry_DEFAULT_EventLog" -SourceName "$($script:PS_NEWOGLogEntry_DEFAULT_EventLogSource)" -Verbose
    }
}


function checkAdminRights (){
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}