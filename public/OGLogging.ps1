function Write-OGLogEntry {
    param(
        [Parameter(Mandatory = $false, HelpMessage = 'Text to log')]
        [ValidateNotNullOrEmpty()]
        [String]$logText,
        [Parameter(Mandatory = $false, HelpMessage = 'Info|Warning|Error')]
        [ValidateSet("Info","Warning","Error","Header","Footer")]
        [String]$logtype = "Info"
    )
    switch($logtype){
        ("Info","Warning","Error"){
            if (!($logText)){
                Write-Error "Please enter a Log Message with the -LogText Switch."
            }
        }
    }
    $callSequence = getCallSequence
    $DateTime = Get-Date
   
    $objLogEntry = [pscustomobject]@{
        Path = "$($myInvocation.ScriptName)";
        Trace = "$($callSequence.Name)";
        Line = "$($callSequence.line)";
        DateTime = $DateTime;
        PID = "$($PID)";
        LogType = "$($logtype)";
        LogText = "$($logText)";
    }

    if ($Script:UseMutex){
        #Attempt to grab mutex.
        $script:objMutex.WaitOne() | Out-Null
        try{
            # Once mutex is grabbed, write to log file.
            writeLogEntry -objLogEntry $objLogEntry
        }
        finally{
            $script:objMutex.ReleaseMutex() | Out-Null
        }
    }
    Else{
        writeLogEntry -objLogEntry $objLogEntry
}

}

function Set-OGLogEntryPath (){
    param(
        [Parameter(Mandatory = $true, HelpMessage = 'Path')]
        [ValidateNotNullOrEmpty()]
        [String]$Path,
        [Parameter(Mandatory = $false, HelpMessage = 'Appends to if already found.')]
        [switch]$Force=$false
    )
    if (Test-Path $Path){
        if (!($Force)){
            Write-Error "Path: '$($Path)' exists. Not changing log file. Specifiy -Force switch to append to file."
            break
        }
    }
    $global:PS_NEWOGLogEntry_DEFAULT_LOGPATH = $Path
    Write-Verbose "PS.SCCMOG.Tools Module will now write to: '$($global:PS_NEWOGLogEntry_DEFAULT_LOGPATH)'"
}

function Enable-OGLogMutex (){
    param(
        [Parameter(Mandatory = $false, HelpMessage = 'Creates a Mutex to enable file handle sharing for writing logs.')]
        [switch]$Enable=$false
    )
    if ($Enable){
        $script:UseMutex = $true
        Write-Verbose "PS.SCCMOG.Tools Module updated Use logging Mutex: $($script:UseMutex)"    
        $script:objMutex = New-Object 'Threading.Mutex' $false, "$script:PS_NEWOGLogEntry_MutexName"
        Write-Verbose "PS.SCCMOG.Tools Module created Mutex with name: $($script:PS_NEWOGLogEntry_MutexName)"    
    }else{
        Write-Error "Specifiy -Enable switch to enable logging mutex."
    }
}

function Set-OGEventLogLogging{
    param(
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [switch]$Enabled,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [switch]$Default,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$EventLog,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$EventLogSource,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [switch]$Disabled
    )
    #If enabled and Default
    if (($Enabled)-and($Default)){
        $script:PS_NEWOGLogEntry_DEFAULT_LogtoEventLog = $true
        Write-Verbose "Enable Event Log logging now set to: $($script:PS_NEWOGLogEntry_DEFAULT_LogtoEventLog)"
        #$script:PS_NEWOGLogEntry_DEFAULT_EventLogSource = (($($myInvocation.ScriptName).Split("\")) | Select-Object -Last 1).Replace(".ps1","")
        Write-Verbose "Event Log logging to Log: '$($script:PS_NEWOGLogEntry_DEFAULT_EventLog)' Source: '$($script:PS_NEWOGLogEntry_DEFAULT_EventLogSource)'"
        initializeEventLogs
    }
    elseif(($Enabled)-and($EventLog)-and($EventLogSource)){
        $script:PS_NEWOGLogEntry_DEFAULT_LogtoEventLog = $true
        $script:PS_NEWOGLogEntry_DEFAULT_EventLog = "$($EventLog)"
        $script:PS_NEWOGLogEntry_DEFAULT_EventLogSource = "$($EventLogSource)"
        Write-Verbose "Enable Event Log logging now set to: $($script:PS_NEWOGLogEntry_DEFAULT_LogtoEventLog)"
        Write-Verbose "Default Event Log now: $($script:PS_NEWOGLogEntry_DEFAULT_EventLog)"
        Write-Verbose "Default Event Log source now: $($script:PS_NEWOGLogEntry_DEFAULT_EventLogSource)"
        initializeEventLogs
        Write-Verbose "Custom Event Log logging to Log: '$($script:PS_NEWOGLogEntry_DEFAULT_EventLog)' Source: '$($script:PS_NEWOGLogEntry_DEFAULT_EventLogSource)'"
    }
    elseif($Disabled){
        $script:PS_NEWOGLogEntry_DEFAULT_LogtoEventLog = $false
        Write-Verbose "Enable Event Log logging now set to: $($script:PS_NEWOGLogEntry_DEFAULT_LogtoEventLog)"
        Write-Verbose "Disabled Event Log logging to Log: '$($script:PS_NEWOGLogEntry_DEFAULT_EventLog)' Source: '$($script:PS_NEWOGLogEntry_DEFAULT_EventLogSource)'"
    }
    else{
        Write-verbose "Please supply Enabled or Disabled switch. -"
    }
}






#############################################################################
#
#Public Functions to be exported. 
#
#############################################################################
<#$Export_Functions = New-Object -TypeName System.Collections.ArrayList
    $Export_Functions.AddRange(@(
        "Write-OGLogEntry",
        "Set-OGLogEntryPath",
        #"Set-OGEventLog", #Removed due to Auto Configuration from Set-OGEventLogLogging
        #"Set-OGEventLogSource", 
        "Enable-OGLogMutex",
        "Set-OGEventLogLogging"
    ))

foreach ($function in $Export_Functions){
    Export-ModuleMember -Function "$($function)"
}#>




#############################################################################
#SFL
#############################################################################

# function Set-OGEventLog (){
#     param(
#         [Parameter(Mandatory = $true, HelpMessage = 'Path')]
#         [ValidateNotNullOrEmpty()]
#         [String]$EventLogName,
#         [Parameter(Mandatory = $false, HelpMessage = 'Appends to if already found.')]
#         [switch]$Force=$false
#     )
#     $result = getEventLog -LogName $EventLogName
#     if ($result){
#         $script:PS_NEWOGLogEntry_DEFAULT_EventLog = $EventLogName
#         Write-Verbose "Success setting Defualt event log to: $($EventLogName)"
#     }
#     Else{
#         if (!($Force)){
#             Write-Error "Event log does not exist with name: '$($EventLogName)' exists. Specifiy -Force switch to create event log to file."
#         }
#         Else{
#             $script:PS_NEWOGLogEntry_DEFAULT_EventLog = $EventLogName
#             newEventLog -LogName $script:PS_NEWOGLogEntry_DEFAULT_EventLog
#         }
#     }
# }


# function Set-OGEventLogSource (){
#     param(
#         [Parameter(Mandatory = $false, HelpMessage = 'Event Log name. Default is set in module.')]
#         [ValidateNotNullOrEmpty()]
#         [String]$EventLogName = "$script:PS_NEWOGLogEntry_DEFAULT_EventLog",
#         [Parameter(Mandatory = $true, HelpMessage = 'The new source name')]
#         [String]$SourceName,
#         [Parameter(Mandatory = $false, HelpMessage = 'Creates it if not found already.')]
#         [switch]$Force=$false
#     )
#     $resultEventLog = getEventLog -LogName $EventLogName
#     if ($resultEventLog){
#         $result = getEventLogSource -eventLog $EventLogName
#         if ($SourceName -in $result){
#             $script:PS_NEWOGLogEntry_DEFAULT_EventLog = $EventLogName
#             Write-Verbose "Success setting Default event log to: $($script:PS_NEWOGLogEntry_DEFAULT_EventLog)"
#             $script:PS_NEWOGLogEntry_DEFAULT_EventLogSource = $SourceName
#             Write-Verbose "Success setting Default event log source to: $($script:PS_NEWOGLogEntry_DEFAULT_EventLogSource)"
#         }
#         Else{
#             if (!($Force)){
#                 Write-Error "Event log: '$($EventLogName)'' found but does not contain log source: '$($SourceName)' Specifiy -Force switch to create event log source."
#             }
#             Else{
#                 newEventLogSource -EventLog "$EventLogName" -EventSource "$($SourceName)"
#                 $script:PS_NEWOGLogEntry_DEFAULT_EventLogSource = $SourceName
#             }
#         }
#     }
#     Else{
#          Write-Error "No Event log with name: '$($EventLogName)'' found please create it first using Set-OGEventLog and the Force switch applied."
#     }
# }