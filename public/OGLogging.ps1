<#
    .SYNOPSIS
        Logging function
    .DESCRIPTION
        This logging function is designed to work automatically after the module is imported.
        It will automatically initialize the logs of the current script to %ProgramData%\Logs\ScriptName.log

    .EXAMPLE
        PS C:\> Write-OGLogEntry -logText "Look at this awesome information log!" -LogType Info
        Logging an information line. (LogType Default is Info so not required.)
    .EXAMPLE
        PS C:\> Write-OGLogEntry -logText "Look at this awesome Warning log!" -LogType Warning
        Logging a Warning line.
    .EXAMPLE
        PS C:\> Write-OGLogEntry -logText "Look at this awesome Error log!" -LogType Error
        Logging an Error line.
    .EXAMPLE
        PS C:\> Write-OGLogEntry -LogType Header
        Log a log header to use at the begining of scripts.
    .EXAMPLE
        PS C:\> Write-OGLogEntry -LogType Footer
        Log a log footer to use at the end of scripts.

    .PARAMETER logText
        Description:    The Text to log.

    .PARAMETER logtype
        Description:    Type to log
        Set:            "Info","Warning","Error","Header","Footer"

    .INPUTS
        String
        Switch
    .OUTPUTS
        String
        Event Log
        CLI
    .NOTES
           Name:       Write-OGLogEntry
           Author:     Richie Schuster - SCCMOG.com
           Website:    https://www.sccmog.com
           Contact:    @RichieJSY
           Created:    2021-08-18
           Updated:    -
    
           Version history:
               1.0.0 - 2021-08-18 Function created
    #>
function Write-OGLogEntry {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $false, Position=0)]
        [ValidateNotNullOrEmpty()]
        [String]$logText,
        [Parameter(Mandatory = $false,  Position=1, HelpMessage = 'Info|Warning|Error|Header|Footer')]
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

<#
.SYNOPSIS
    Sets the default logging path of Write-OGLogEntry
.DESCRIPTION
    Sets the default logging path of Write-OGLogEntry.
    NOTE: Run this at the begining of the script.
.EXAMPLE
    PS C:\> Set-OGLogEntryPath -Path "$env:programdata\logs\TestingOverWrite.Log" -Force -Verbose
    Sets the default logging path of Write-OGLogEntry to "$env:programdata\logs\TestingOverWrite.Log"

.PARAMETER Path
The path to store the log file.

.PARAMETER Force
If used will append to a current log file if one is foun dthe new location.

.INPUTS
    Full string path to log file.

.OUTPUTS
    Output (if any)

.NOTES
        Name:       Set-OGLogEntryPath
        Author:     Richie Schuster - SCCMOG.com
        Website:    https://www.sccmog.com
        Contact:    @RichieJSY
        Created:    2021-08-18
        Updated:    -

        Version history:
            1.0.0 - 2021-08-18 Function created
#>
function Set-OGLogEntryPath (){
    [cmdletbinding()]
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


<#
.SYNOPSIS
    Sets the default logging Root path of Write-OGLogEntry
.DESCRIPTION
    Sets the default logging path of Write-OGLogEntry.
    NOTE: Run this at the begining of the script.
.EXAMPLE
    PS C:\> Set-OGLogEntryRootPath -Path "$env:programdata\logs" -Force -Verbose
    Sets the default logging root path of Write-OGLogEntry to "$env:programdata\logs"

.PARAMETER Path
The path to store the log file.

.PARAMETER Force
If used will append to a current log file if one is foun dthe new location.

.INPUTS
    Full string path to log file.

.OUTPUTS
    Output (if any)

.NOTES
        Name:       Set-OGLogEntryRootPath
        Author:     Richie Schuster - SCCMOG.com
        Website:    https://www.sccmog.com
        Contact:    @RichieJSY
        Created:    2022-01-24
        Updated:    -

        Version history:
            1.0.0 - 2022-01-24 Function created
#>
function Set-OGLogEntryRootPath (){
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = 'Path')]
        [ValidateNotNullOrEmpty()]
        [String]$Path,
        [Parameter(Mandatory = $false, HelpMessage = 'Appends to if already found.')]
        [switch]$Force=$false
    )
    if (!(Test-Path $Path -PathType Container)){
        if (!($Force)){
            Write-Error "Path: '$($Path)' does not exist. Specifiy -Force switch to create the directory."
            break
        }
        else{
            New-Item -Path "$($Path)" -Force
            Write-Verbose "Created: '$($Path)' "
        }
    }
    $global:PS_NEWOGLogEntry_DEFAULT_LOGPATH = "$($Path)\$($global:PS_SCCMOG_cScriptName).log"
    Write-Verbose "PS.SCCMOG.Tools Module will now write logs to: '$($Path)'"
    Write-Verbose "PS.SCCMOG.Tools Module log Name: '$($global:PS_SCCMOG_cScriptName)'"
}


<#
.SYNOPSIS
    Create logging mutex to allow logging to the same file from multiple scripts at the same time.
.DESCRIPTION
    When this function is called it will create a logging mutex to allow logging 
    to the same file from multiple scripts at the same time.
.EXAMPLE
    PS C:\> Enable-OGLogMutex -Enable -Verbose
    Create logging mutex to allow logging to the same file from multiple scripts 
    at the same time.

.PARAMETER Enable
    If specified will create the mutex.

.NOTES
    Name:       Enable-OGLogMutex
    Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-08-18
    Updated:    -

    Version history:
        1.0.0 - 2021-08-18 Function created
#>
function Enable-OGLogMutex (){
    [cmdletbinding()]
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


<#
.SYNOPSIS
    Allow Write-OGLogEntry to log to the event log as well.
.DESCRIPTION
    Allow Write-OGLogEntry to log to the event log as well. 
    It can create a new event log and source or just use the script default.

.EXAMPLE
    PS C:\> Set-OGEventLogLogging -Enabled -Default -Verbose
    Enable Eventlog Logging for the function Write-OGLogEntry and use the module defaults. Will auto create if not found ;)

.EXAMPLE
    PS C:\> Set-OGEventLogLogging -Enabled -EventLog "MY Event Log" -EventLogSource "My Event Source" -Verbose
    Enable Eventlog Logging for the function Write-OGLogEntry and use custom Event Log and Source. Will auto create if not found ;)

.EXAMPLE
    PS C:\> Set-OGEventLogLogging -Disabled
    Disables Eventlog Logging for function Write-OGLogEntry.

.PARAMETER Enabled
Enables Event log logging

.PARAMETER Default
States to setup eventlog and eventsource with module defaults

.PARAMETER EventLog
Use custom EventLog Name. Will create log if not found. Paired with EventLogSource Parameter.

.PARAMETER EventLogSource
Use custom EventLog Source Name. Will create log if not found. Paired with EventLog Parameter.

.PARAMETER Disabled
Disable event log logging.

.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
       Name:       Set-OGEventLogLogging
       Author:     Richie Schuster - SCCMOG.com
       Website:    https://www.sccmog.com
       Contact:    @RichieJSY
       Created:    2021-08-18
       Updated:    -

       Version history:
           1.0.0 - 2021-08-18 Function created
#>
function Set-OGEventLogLogging{
    [cmdletbinding()]
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


$Export = @(
    "Enable-OGLogMutex",
    "Set-OGEventLogLogging",
    "Set-OGLogEntryPath",
    "Write-OGLogEntry",
    "Set-OGLogEntryRootPath"
)

FOREACH ($module in $Export){
    Export-ModuleMember $module
}