#Get all scripts module files
$publicFiles = @( Get-ChildItem $PSScriptRoot\public\*.ps1)
$privateFiles = @( Get-ChildItem $PSScriptRoot\private\*.ps1)

#Load Module files
#$scripts = @( $publicFiles + $privateFiles)
foreach ($privateScript in $privateFiles) {
    try {
        Write-Verbose "Importing Private module file: '$($privateScript.Name)'" -Verbose
        . $privateScript.FullName
    }
    catch {
        Write-error "Failed to import Private module file: '$($privateScript.FullName)'. $_" -Verbose
    }
}#>
foreach ($publicScript in $publicFiles) {
    try {
        Write-Verbose "Importing Public module file: '$($publicScript.Name)'" -Verbose
        . $publicScript.FullName
    }
    catch {
        Write-error "Failed to import Publicmodule file: '$($publicScript.FullName)'. $_" -Verbose
    }
}

function IntializePSSCCMOGModule () {
    #Global
    $global:PS_NEWOGLogEntry_DEFAULT_LOGDIR = "$($ENV:ProgramData)\Logs"
    $defaultLogDetails = getDefaultLogDetails
    $global:PS_SCCMOG_cScriptName = "$($defaultLogDetails.ScriptName)"
    $global:PS_NEWOGLogEntry_DEFAULT_LOGPATH = "$($defaultLogDetails.DefaultLogFilePath)"

    #Script
    $script:PS_NEWOGLogEntry_DEFAULT_EventLog = "Clarivate Deployment"
    $script:PS_NEWOGLogEntry_DEFAULT_EventLogSource = "$($defaultLogDetails.ScriptName)"
    $script:PS_NEWOGLogEntry_DEFAULT_LogtoEventLog = $false
    $script:UseMutex = $false
    $script:PS_NEWOGLogEntry_MutexName = "Loggit"
}

IntializePSSCCMOGModule

Write-Verbose "PS.SCCMOG.Tools Module will write to Global Variable: $global:PS_NEWOGLogEntry_DEFAULT_LOGPATH" -Verbose
Write-Verbose "PS.SCCMOG.Tools Module event Log logging enabled: $script:PS_NEWOGLogEntry_DEFAULT_LogtoEventLog" -Verbose
Write-Verbose "PS.SCCMOG.Tools Module will write to Event Log: '$script:PS_NEWOGLogEntry_DEFAULT_EventLog' Event Source: '$script:PS_NEWOGLogEntry_DEFAULT_EventLogSource'" -Verbose
Write-Verbose "PS.SCCMOG.Tools Module Use logging Mutex: $($script:UseMutex)" -Verbose