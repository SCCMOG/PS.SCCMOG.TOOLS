#Import Module
Remove-Module -name PS.SCCMOG.Tools -Force -ErrorAction SilentlyContinue
Import-Module .\PS.SCCMOG.Tools.psd1 -Force -Verbose

#######################################################################################
#Begin Region
#######################################################################################

Set-OGLogEntryPath -Path "$env:programdata\logs\TestingOverWrite.Log" -Force -Verbose
Enable-OGLogMutex -Enable -Verbose
Set-OGEventLogLogging -Enabled -Default -Verbose
Write-OGLogEntry -logtype Header

######################################################################################
#Global Variables
######################################################################################
# $global:PS_NEWOGLogEntry_DEFAULT_LOGDIR = ""
# $global:PS_SCCMOG_cScriptName = ""
# $global:PS_NEWOGLogEntry_DEFAULT_LOGPATH = ""

#######################################################################################
#Main Region
#######################################################################################

Write-OGLogEntry -logText "Testing Error" -logtype Error
Write-OGLogEntry -logText "Testing Info" -logtype Info
Write-OGLogEntry -logText "Testing Warning" -logtype Warning

function simplefunction (){
    Write-OGLogEntry -logText "simplefunction" -logtype Warning   
    #Get-PSCallStack | Select-Object -Property *
}

function anothersimplefunction (){
    Write-OGLogEntry -logText "anothersimplefunction" -logtype Warning  
    simplefunction
}
anothersimplefunction
#Spawn Another Process
$processResult = $null
$processResult = Start-Process Powershell -argument "-noprofile .\Tester2.ps1 -LogFilePath '$Global:PS_NEWOGLogEntry_DEFAULT_LOGPATH'" -NoNewWindow -PassThru
$processResult.WaitForExit()
#$processResult

#Get-PSCallStack
#######################################################################################
#Finish Region
#######################################################################################
Write-OGLogEntry -logtype Footer
