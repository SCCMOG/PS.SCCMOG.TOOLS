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
#Main Region
#######################################################################################

Write-OGLogEntry -logText "Testing"
Write-OGLogEntry -logText "Testing" -Logtype Warning
Write-OGLogEntry -logText "Testing" -Logtype Error

#Get-PSCallStack
#######################################################################################
#Finish Region
#######################################################################################
Write-OGLogEntry -logtype Footer
