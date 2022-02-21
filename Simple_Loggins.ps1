#Import Module
Remove-Module -name PS.SCCMOG.Tools -Force -ErrorAction SilentlyContinue
Import-Module .\PS.SCCMOG.Tools.psd1 -Force -Verbose

#######################################################################################
#Begin Region
#######################################################################################

Write-OGLogEntry -logtype Header

######################################################################################
#Global Variables
######################################################################################
# $global:PS_NEWOGLogEntry_DEFAULT_LOGDIR = ""
# $global:PS_SCCMOG_cScriptName = ""
# $global:PS_NEWOGLogEntry_DEFAULT_LOGPATH = ""

#######################################################################################
#Region Main
#######################################################################################

#Will log to script name.
Set-OGEventLogLogging -Enabled -Default -Verbose

Write-OGLogEntry -logText "Testing" -Verbose
Write-OGLogEntry -logText "Testing" -Logtype Warning
Write-OGLogEntry -logText "Testing" -Logtype Error

#Set-OGEventLogLogging -Enabled -EventLog "Test" -EventLogSource "Mysource" -Verbose

#Get-PSCallStack
#######################################################################################
#endRegion Main
#######################################################################################
Write-OGLogEntry -logtype Footer