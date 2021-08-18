[CmdletBinding()]
param(
	[string]$LogFilePath
)

Import-Module .\PS.SCCMOG.Tools.psd1 -Force
Set-OGLogEntryPath -Path $LogFilePath -Force -Verbose
Enable-OGLogMutex -Enable -Verbose
Write-OGLogEntry -logtype Header
Write-OGLogEntry -logText "$LogFilePath" -logtype Warning
#$Test
Start-Sleep 3
#Write-host $Global:PS_NEWOGLogEntry_DEFAULT_LOGPATH
#Get-PSCallStack
$Ted = "bill"


Write-OGLogEntry -logtype Footer

return $ted
