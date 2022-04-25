##################################################################################################################################
# Current User Region
##################################################################################################################################

<#
.SYNOPSIS
    Gets logged on user
.DESCRIPTION
    This function gets all users that are currently connected to a device and then returns the Active user as a custom PS Object.
.EXAMPLE
    PS C:\> Get-OGLoggedOnUser
    
    Returns a $CurrentLoggedOnUser Object with properties:

            USERNAME          : rkcsj
            USERPROFILE       : C:\Users\rkcsj
            USERDOMAIN        : RSNUC
            SID               : S-1-5-21-1291444473-292444476-2264444970-1001
            DNSDOMAIN         : SCCMOG.local
            LOGONSERVER       : \\RSNUC
            HOMEPATH          : \Users\rkcsj
            HOMEDRIVE         : C:
            APPDATA           : C:\Users\rkcsj\AppData\Roaming
            LOCALAPPDATA      : C:\Users\rkcsj\AppData\Local
            Domain_SamAccount : RSNUC\rkcsj
            AADUserName       : richie.schuster@sccmog.com
            AADUserObjID      : 68fg9e49-4b39-4f13-a0bf-79b4f94d0691

.OUTPUTS
    Returns a $CurrentLoggedOnUser PowerShell Object with properties:
        
            USERNAME          : rkcsj
            USERPROFILE       : C:\Users\rkcsj
            USERDOMAIN        : RSNUC
            SID               : S-1-5-21-1291444473-292444476-2264444970-1001
            DNSDOMAIN         : SCCMOG.local
            LOGONSERVER       : \\RSNUC
            HOMEPATH          : \Users\rkcsj
            HOMEDRIVE         : C:
            APPDATA           : C:\Users\rkcsj\AppData\Roaming
            LOCALAPPDATA      : C:\Users\rkcsj\AppData\Local
            Domain_SamAccount : RSNUC\rkcsj
            AADUserName       : richie.schuster@sccmog.com
            AADUserObjID      : 68fg9e49-4b39-4f13-a0bf-79b4f94d0691

.NOTES
    Name:        Get-OGLoggedOnUser   
    Author:      Richie Schuster - SCCMOG.com
    Website:     https://www.sccmog.com
    Contact:     @RichieJSY
    Created:     2021-06-14
    Updated:     -
    
    Version history:
    1.0.0 - (2021-06-14) Function created
    1.1.0 - 2021-08-19 - Added Azure AD information.
#>  
function Get-OGLoggedOnUser{
    [cmdletbinding()]
    $CurrentLoggedOnUser = $null
    $AllUserCheck = @()
    Write-OGLogEntry -Logtext "Getting Currently logged on user for machine: $($ENV:COMPUTERNAME)"
    $UserQuery = query user
    foreach($User in $UserQuery){
        $Username        = $User.Substring(1,22).trim()
        $SessionName     = $User.Substring(23,19).trim()
        $Id              = $User.Substring(42,4).trim()
        $State           = $User.Substring(46,8).trim()
        $IdleTime        = $User.Substring(54,11).trim()

        $UserCheck  = New-Object psobject
        $UserCheck | Add-Member -MemberType NoteProperty -Name Username -Value        $Username
        $UserCheck | Add-Member -MemberType NoteProperty -Name SessionName -Value     $SessionName
        $UserCheck | Add-Member -MemberType NoteProperty -Name Id -Value              $Id
        $UserCheck | Add-Member -MemberType NoteProperty -Name State -Value           $State
        $UserCheck | Add-Member -MemberType NoteProperty -Name IdleTime -Value        $IdleTime
        $AllUserCheck += $UserCheck
    }
    #Remove first entry.
    $skip = $true
    $ParsedAllUserArray = @()
    foreach($line in $AllUserCheck){
        if($skip -eq $true){
            $skip = $false
        }
        else{
            $ParsedAllUserArray += $line
        }
    }
    #Check session time
    foreach($ParsedUserCheck in $ParsedAllUserArray){
        if(($ParsedUserCheck.SessionName -ne "")){
            if($ParsedUserCheck.IdleTime -match '^[0-9]+$'){
                if($ParsedUserCheck.IdleTime -le '60'){
                    $ActiveUser = $ParsedUserCheck
                }
                else{
                    $ActiveUser = $null
                }
            }
            else{
                $ActiveUser = $ParsedUserCheck
            }
        }
    }
    if ($ActiveUser){
        $CurrentlyLoggedOnUserSIDs = ((Get-ChildItem "registry::HKU" -ErrorAction SilentlyContinue).name | Where-Object { (($_ -notlike "*_classes") -and ($_ -notlike "*.default") -and ($_ -notlike "*S-1-5-18") -and ($_ -notlike "*S-1-5-19"))}) -replace "HKEY_USERS\\",""
        foreach($CurrentlyLoggedOnUserSID in $CurrentlyLoggedOnUserSIDs)
        {
            $CLOUsername = (Get-ItemProperty "Registry::hku\$CurrentlyLoggedOnUserSID\Volatile Environment" -ErrorAction SilentlyContinue).Username
            if($CLOUsername -eq $ActiveUser.UserName)
            {
                $SID_RegVirtualEnv = Get-ItemProperty "Registry::hku\$($CurrentlyLoggedOnUserSID)\Volatile Environment"
                $MSO365UserIdentityRoot = "Registry::hku\$($CurrentlyLoggedOnUserSID)\SOFTWARE\Microsoft\Office\16.0\Common\Identity\Identities"
                $MSIdentityCacheCurrentUser = "Registry::hklm\SOFTWARE\Microsoft\IdentityStore\Cache\$($CurrentlyLoggedOnUserSID)\IdentityCache\$($CurrentLoggedOnUserSID)"
                if(Test-Path $MSO365UserIdentityRoot){
                    $MSO365UserIdentityRoot = Get-ChildItem "$MSO365UserIdentityRoot" | Where-Object {$_.Name -like "*_ADAL"}
                    if ($MSO365UserIdentityRoot){
                        $objLoggedOnUserADAL = $MSO365UserIdentityRoot | Select-Object -First 1
                        $AADUName = "$($objLoggedOnUserADAL.GetValue("EmailAddress"))"
                        $AADObjID = "$($objLoggedOnUserADAL.GetValue("ProviderId"))"
                    }
                }
                if ($AADUName -like ""){
                    if(Test-Path $MSIdentityCacheCurrentUser) {
                        $objCurrentUserMSCachedIdentity = Get-ItemProperty "$MSIdentityCacheCurrentUser"
                        $AADUName = "$($objCurrentUserMSCachedIdentity.UserName)"
                        $AADObjID = "NA"
                    }
                    else{
                        $AADUName = "NA"
                        $AADObjID = "NA"
                    }
                }
                $LoggedInUser  = New-Object psobject
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name USERNAME -Value            $SID_RegVirtualEnv.USERNAME
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name USERPROFILE -Value         $SID_RegVirtualEnv.USERPROFILE
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name USERDOMAIN -Value          $SID_RegVirtualEnv.USERDOMAIN
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name SID -Value                 $CurrentlyLoggedOnUserSID
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name DNSDOMAIN -Value           $SID_RegVirtualEnv.USERDNSDOMAIN
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name LOGONSERVER -Value         $SID_RegVirtualEnv.LOGONSERVER
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name HOMEPATH -Value            $SID_RegVirtualEnv.HOMEPATH
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name HOMEDRIVE -Value           $SID_RegVirtualEnv.HOMEDRIVE
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name APPDATA -Value             $SID_RegVirtualEnv.APPDATA
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name LOCALAPPDATA -Value        $SID_RegVirtualEnv.LOCALAPPDATA
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name Domain_SamAccount -Value   "$($SID_RegVirtualEnv.USERDOMAIN)\$($SID_RegVirtualEnv.USERNAME)"
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name Email -Value               $AADUName
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name AADUserObjID -Value        $AADObjID
                $CurrentLoggedOnUser = $LoggedInUser
            }
        }
    }
    Else{
        Write-OGLogEntry -Logtext "ERROR No logged on user for machine: $($ENV:COMPUTERNAME)" -logType Error
        return $CurrentLoggedOnUser
    }
    Write-OGLogEntry -Logtext "Current logged on user: $($CurrentLoggedOnUser.USERNAME)"
    return $CurrentLoggedOnUser
}

<#
.SYNOPSIS
    Gets logged on user from Win32_ComputerSystem and Win32_UserProfile
.DESCRIPTION
    This function gets all users that are currently connected to a device using Win32_UserProfile and then returns the Active user as a custom PS Object.
.EXAMPLE
    PS C:\> Get-OGLoggedOnUserCombined
    
    Returns a $CurrentLoggedOnUser Object with properties:

            USERNAME          : rkcsj
            USERPROFILE       : C:\Users\rkcsj
            USERDOMAIN        : RSNUC
            SID               : S-1-5-21-1291444473-292444476-2264444970-1001
            DNSDOMAIN         : SCCMOG.local
            LOGONSERVER       : \\RSNUC
            HOMEPATH          : \Users\rkcsj
            HOMEDRIVE         : C:
            APPDATA           : C:\Users\rkcsj\AppData\Roaming
            LOCALAPPDATA      : C:\Users\rkcsj\AppData\Local
            Domain_SamAccount : RSNUC\rkcsj
            AADUserName       : richie.schuster@sccmog.com
            AADUserObjID      : 68fg9e49-4b39-4f13-a0bf-79b4f94d0691

.OUTPUTS
    Returns a $CurrentLoggedOnUser PowerShell Object with properties:
        
            USERNAME          : rkcsj
            USERPROFILE       : C:\Users\rkcsj
            USERDOMAIN        : RSNUC
            SID               : S-1-5-21-1291444473-292444476-2264444970-1001
            DNSDOMAIN         : SCCMOG.local
            LOGONSERVER       : \\RSNUC
            HOMEPATH          : \Users\rkcsj
            HOMEDRIVE         : C:
            APPDATA           : C:\Users\rkcsj\AppData\Roaming
            LOCALAPPDATA      : C:\Users\rkcsj\AppData\Local
            Domain_SamAccount : RSNUC\rkcsj
            AADUserName       : richie.schuster@sccmog.com
            AADUserObjID      : 68fg9e49-4b39-4f13-a0bf-79b4f94d0691

.NOTES
    Name:        Get-OGLoggedOnUserCombined   
    Author:      Richie Schuster - SCCMOG.com
    Website:     https://www.sccmog.com
    Contact:     @RichieJSY
    Created:     2021-11-25
    Updated:     2022-02-17
    
    Version history:
    1.0.0 - 2021-11-25 Function created
    2.0.0 -  2022-02-17 Modified WMI profiles search for Volatile ENV 

#>  
function Get-OGLoggedOnUserCombined{
    [cmdletbinding()]
    $CurrentLoggedOnUser = $null
    Write-OGLogEntry -Logtext "Getting current profile list from from WMI for machine: $($ENV:COMPUTERNAME)"
    $UserProfiles = Get-WmiObject -Class Win32_UserProfile | Where-Object {($_.SID -notmatch "^S-1-5-\d[18|19|20]$")}
    Write-OGLogEntry -Logtext "Found $(($UserProfiles|Measure-Object).Count) user profile(s) in WMI for machine: $($ENV:COMPUTERNAME)"
    Write-OGLogEntry -Logtext "Searching user registry profile(s) for Volatile Environment key."
    $ActiveUser = $null
    foreach ($profile in $UserProfiles){
        if ((Test-Path -Path "Registry::hku\$($profile.SID)\Volatile Environment" -PathType Container)-and($profile.Loaded)){
            Write-OGLogEntry -Logtext "Found active user loaded."
            $ActiveUser = $profile
            break
        }
    }
    if (($ActiveUser|Measure-Object).Count -eq 1){
            $SID_RegVirtualEnv = Get-ItemProperty "Registry::hku\$($ActiveUser.SID)\Volatile Environment" -ErrorAction SilentlyContinue
            if($SID_RegVirtualEnv)
            {
                $MSO365UserIdentityRoot = "Registry::hku\$($ActiveUser.SID)\SOFTWARE\Microsoft\Office\16.0\Common\Identity\Identities"
                $MSIdentityCacheCurrentUser = "Registry::hklm\SOFTWARE\Microsoft\IdentityStore\Cache\$($ActiveUser.SID)\IdentityCache\$($ActiveUser.SID)"
                $AuthLogonUI = "Registry::hklm\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
                if(Test-Path $MSO365UserIdentityRoot){
                    $MSO365UserIdentityRoot = Get-ChildItem "$MSO365UserIdentityRoot" | Where-Object {$_.Name -like "*_ADAL"}
                    if ($MSO365UserIdentityRoot){
                        $objLoggedOnUserADAL = $MSO365UserIdentityRoot | Select-Object -First 1
                        $AADUName = "$($objLoggedOnUserADAL.GetValue("EmailAddress"))"
                        $AADObjID = "$($objLoggedOnUserADAL.GetValue("ProviderId"))"
                    }
                }
                if ($AADUName -like ""){
                    if(Test-Path $MSIdentityCacheCurrentUser) {
                        $objCurrentUserMSCachedIdentity = Get-ItemProperty "$MSIdentityCacheCurrentUser"
                        $AADUName = "$($objCurrentUserMSCachedIdentity.UserName)"
                        $AADObjID = "NA"
                    }
                    else{
                        $AADUName = "NA"
                        $AADObjID = "NA"
                    }
                }
                if (Test-Path $AuthLogonUI){
                    $AuthLogonUIData = Get-ItemProperty "$AuthLogonUI" 
                    if ($AuthLogonUIData.LastLoggedOnDisplayName){
                        $UserDisplayName = "$($AuthLogonUIData.LastLoggedOnDisplayName)"
                    }
                    else{
                        $UserDisplayName = "$($SID_RegVirtualEnv.USERNAME)"
                    }
                }
                $LoggedInUser  = New-Object psobject
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name USERNAME -Value            $SID_RegVirtualEnv.USERNAME
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name USERPROFILE -Value         $SID_RegVirtualEnv.USERPROFILE
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name USERDOMAIN -Value          $SID_RegVirtualEnv.USERDOMAIN
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name SID -Value                 $ActiveUser.SID
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name DNSDOMAIN -Value           $SID_RegVirtualEnv.USERDNSDOMAIN
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name LOGONSERVER -Value         $SID_RegVirtualEnv.LOGONSERVER
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name HOMEPATH -Value            $SID_RegVirtualEnv.HOMEPATH
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name HOMEDRIVE -Value           $SID_RegVirtualEnv.HOMEDRIVE
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name APPDATA -Value             $SID_RegVirtualEnv.APPDATA
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name LOCALAPPDATA -Value        $SID_RegVirtualEnv.LOCALAPPDATA
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name Domain_SamAccount -Value   "$($SID_RegVirtualEnv.USERDOMAIN)\$($SID_RegVirtualEnv.USERNAME)"
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name Email -Value               $AADUName
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name AADUserObjID -Value        $AADObjID
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name DisplayName -Value         $UserDisplayName
                $CurrentLoggedOnUser = $LoggedInUser
            }
    }
    Else{
        Write-OGLogEntry -Logtext "ERROR No logged on active user for machine: $($ENV:COMPUTERNAME)" -logType Error
        return $CurrentLoggedOnUser
    }
    Write-OGLogEntry -Logtext "Current logged on user: $($CurrentLoggedOnUser.USERNAME)"
    return $CurrentLoggedOnUser
}

<#
.SYNOPSIS
    Gets logged on user from Win32_UserProfile
.DESCRIPTION
    This function gets all users that are currently connected to a device using Win32_UserProfile and then returns the Active user as a custom PS Object.
.EXAMPLE
    PS C:\> Get-OGLoggedOnUserWMI
    
    Returns a $CurrentLoggedOnUser Object with properties:

            USERNAME          : rkcsj
            USERPROFILE       : C:\Users\rkcsj
            USERDOMAIN        : RSNUC
            SID               : S-1-5-21-1291444473-292444476-2264444970-1001
            DNSDOMAIN         : SCCMOG.local
            LOGONSERVER       : \\RSNUC
            HOMEPATH          : \Users\rkcsj
            HOMEDRIVE         : C:
            APPDATA           : C:\Users\rkcsj\AppData\Roaming
            LOCALAPPDATA      : C:\Users\rkcsj\AppData\Local
            Domain_SamAccount : RSNUC\rkcsj
            AADUserName       : richie.schuster@sccmog.com
            AADUserObjID      : 68fg9e49-4b39-4f13-a0bf-79b4f94d0691

.OUTPUTS
    Returns a $CurrentLoggedOnUser PowerShell Object with properties:
        
            USERNAME          : rkcsj
            USERPROFILE       : C:\Users\rkcsj
            USERDOMAIN        : RSNUC
            SID               : S-1-5-21-1291444473-292444476-2264444970-1001
            DNSDOMAIN         : SCCMOG.local
            LOGONSERVER       : \\RSNUC
            HOMEPATH          : \Users\rkcsj
            HOMEDRIVE         : C:
            APPDATA           : C:\Users\rkcsj\AppData\Roaming
            LOCALAPPDATA      : C:\Users\rkcsj\AppData\Local
            Domain_SamAccount : RSNUC\rkcsj
            AADUserName       : richie.schuster@sccmog.com
            AADUserObjID      : 68fg9e49-4b39-4f13-a0bf-79b4f94d0691

.NOTES
    Name:        Get-OGLoggedOnUserWMI   
    Author:      Richie Schuster - SCCMOG.com
    Website:     https://www.sccmog.com
    Contact:     @RichieJSY
    Created:     2021-11-25
    Updated:     -
    
    Version history:
    1.0.0 - 2021-11-25 Function created
#>  
function Get-OGLoggedOnUserWMI{
    [cmdletbinding()]
    $CurrentLoggedOnUser = $null
    Write-OGLogEntry -Logtext "Getting currently logged from WMI on user for machine: $($ENV:COMPUTERNAME)"
    $ActiveUser = Get-WmiObject -Class Win32_UserProfile | Where-Object {($_.SID -notmatch "^S-1-5-\d[18|19|20]$")} | Sort-Object -Property LastUseTime -Descending | Select-Object -First 1
    if ($ActiveUser.Loaded){
            $SID_RegVirtualEnv = Get-ItemProperty "Registry::hku\$($ActiveUser.SID)\Volatile Environment" -ErrorAction SilentlyContinue
            if($SID_RegVirtualEnv)
            {
                $MSO365UserIdentityRoot = "Registry::hku\$($ActiveUser.SID)\SOFTWARE\Microsoft\Office\16.0\Common\Identity\Identities"
                $MSIdentityCacheCurrentUser = "Registry::hklm\SOFTWARE\Microsoft\IdentityStore\Cache\$($ActiveUser.SID)\IdentityCache\$($ActiveUser.SID)"
                if(Test-Path $MSO365UserIdentityRoot){
                    $MSO365UserIdentityRoot = Get-ChildItem "$MSO365UserIdentityRoot" | Where-Object {$_.Name -like "*_ADAL"}
                    if ($MSO365UserIdentityRoot){
                        $objLoggedOnUserADAL = $MSO365UserIdentityRoot | Select-Object -First 1
                        $AADUName = "$($objLoggedOnUserADAL.GetValue("EmailAddress"))"
                        $AADObjID = "$($objLoggedOnUserADAL.GetValue("ProviderId"))"
                    }
                }
                if ($AADUName -like ""){
                    if(Test-Path $MSIdentityCacheCurrentUser) {
                        $objCurrentUserMSCachedIdentity = Get-ItemProperty "$MSIdentityCacheCurrentUser"
                        $AADUName = "$($objCurrentUserMSCachedIdentity.UserName)"
                        $AADObjID = "NA"
                    }
                    else{
                        $AADUName = "NA"
                        $AADObjID = "NA"
                    }
                }
                $LoggedInUser  = New-Object psobject
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name USERNAME -Value            $SID_RegVirtualEnv.USERNAME
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name USERPROFILE -Value         $SID_RegVirtualEnv.USERPROFILE
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name USERDOMAIN -Value          $SID_RegVirtualEnv.USERDOMAIN
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name SID -Value                 $ActiveUser.SID
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name DNSDOMAIN -Value           $SID_RegVirtualEnv.USERDNSDOMAIN
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name LOGONSERVER -Value         $SID_RegVirtualEnv.LOGONSERVER
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name HOMEPATH -Value            $SID_RegVirtualEnv.HOMEPATH
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name HOMEDRIVE -Value           $SID_RegVirtualEnv.HOMEDRIVE
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name APPDATA -Value             $SID_RegVirtualEnv.APPDATA
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name LOCALAPPDATA -Value        $SID_RegVirtualEnv.LOCALAPPDATA
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name Domain_SamAccount -Value   "$($SID_RegVirtualEnv.USERDOMAIN)\$($SID_RegVirtualEnv.USERNAME)"
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name Email -Value               $AADUName
                $LoggedInUser | Add-Member -MemberType NoteProperty -Name AADUserObjID -Value        $AADObjID
                $CurrentLoggedOnUser = $LoggedInUser
            }
    }
    Else{
        Write-OGLogEntry -Logtext "ERROR No logged on user for machine: $($ENV:COMPUTERNAME)" -logType Error
        return $CurrentLoggedOnUser
    }
    Write-OGLogEntry -Logtext "Current logged on user: $($CurrentLoggedOnUser.USERNAME)"
    return $CurrentLoggedOnUser
}

<#
.SYNOPSIS
Launches the specified file as the current logged on user if running from the 'NT AUTHORITY\SYSTEM' context.
"Allow user to view and interact with the program installation" must be selected.
.DESCRIPTION
Launches the specified file as the current logged on user if running from the 'NT AUTHORITY\SYSTEM' context.
"Allow user to view and interact with the program installation" must be selected.
.PARAMETER FilePath
File path to launch

.PARAMETER Arguments
Arguments for the file that is to be launched. 

.EXAMPLE
Invoke-OGStartProcessAsCurrentUser -FilePath "$scriptRoot\Notification\Notify_User.ps1"

.EXAMPLE
Invoke-OGStartProcessAsCurrentUser -FilePath "$scriptRoot\Notification\Notify_User.ps1" -Arguments "-Colour Purple"

.NOTES
    Name:       Invoke-OGStartProcessAsCurrentUser       
	Author:     Richie Schuster - SCCMOG.com
    Source:     https://github.com/imabdk/Toast-Notification-Script
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2021-09-21
    Updated:    -
    Notes:      This function has been adapted from the famous toast notification script at the above source.
    
    Version history:
    1.0.0 - 2021-09-21 Function created
#>
function Invoke-OGStartProcessAsCurrentUser{
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$FilePath,
        [parameter(Mandatory = $false)]
        [string]$Arguments
    )
    If (!(([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name -eq "NT AUTHORITY\SYSTEM")) {
        $message = "This function Invoke-OGStartProcessAsCurrentUser can only be run as 'NT AUTHORITY\SYSTEM'"
        Write-OGLogEntry $message -logtype Error
        throw $message
    }
$Source = @"
using System;
using System.Runtime.InteropServices;

namespace Runasuser
{
    public static class ProcessExtensions
    {
        #region Win32 Constants

        private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int CREATE_NO_WINDOW = 0x08000000;

        private const int CREATE_NEW_CONSOLE = 0x00000010;

        private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
        private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        #endregion

        #region DllImports

        [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            String lpApplicationName,
            String lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandle,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        private static extern bool DuplicateTokenEx(
            IntPtr ExistingTokenHandle,
            uint dwDesiredAccess,
            IntPtr lpThreadAttributes,
            int TokenType,
            int ImpersonationLevel,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hSnapshot);

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll")]
        private static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern int WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved,
            int Version,
            ref IntPtr ppSessionInfo,
            ref int pCount);

        #endregion

        #region Win32 Structs

        private enum SW
        {
            SW_HIDE = 0,
            SW_SHOWNORMAL = 1,
            SW_NORMAL = 1,
            SW_SHOWMINIMIZED = 2,
            SW_SHOWMAXIMIZED = 3,
            SW_MAXIMIZE = 3,
            SW_SHOWNOACTIVATE = 4,
            SW_SHOW = 5,
            SW_MINIMIZE = 6,
            SW_SHOWMINNOACTIVE = 7,
            SW_SHOWNA = 8,
            SW_RESTORE = 9,
            SW_SHOWDEFAULT = 10,
            SW_MAX = 10
        }

        private enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3,
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        private enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public readonly UInt32 SessionID;

            [MarshalAs(UnmanagedType.LPStr)]
            public readonly String pWinStationName;

            public readonly WTS_CONNECTSTATE_CLASS State;
        }

        #endregion

        // Gets the user token from the currently active session
        private static bool GetSessionUserToken(ref IntPtr phUserToken)
        {
            var bResult = false;
            var hImpersonationToken = IntPtr.Zero;
            var activeSessionId = INVALID_SESSION_ID;
            var pSessionInfo = IntPtr.Zero;
            var sessionCount = 0;

            // Get a handle to the user access token for the current active session.
            if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount) != 0)
            {
                var arrayElementSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                var current = pSessionInfo;

                for (var i = 0; i < sessionCount; i++)
                {
                    var si = (WTS_SESSION_INFO)Marshal.PtrToStructure((IntPtr)current, typeof(WTS_SESSION_INFO));
                    current += arrayElementSize;

                    if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                    {
                        activeSessionId = si.SessionID;
                    }
                }
            }

            // If enumerating did not work, fall back to the old method
            if (activeSessionId == INVALID_SESSION_ID)
            {
                activeSessionId = WTSGetActiveConsoleSessionId();
            }

            if (WTSQueryUserToken(activeSessionId, ref hImpersonationToken) != 0)
            {
                // Convert the impersonation token to a primary token
                bResult = DuplicateTokenEx(hImpersonationToken, 0, IntPtr.Zero,
                    (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, (int)TOKEN_TYPE.TokenPrimary,
                    ref phUserToken);

                CloseHandle(hImpersonationToken);
            }

            return bResult;
        }

        public static bool StartProcessAsCurrentUser(string appPath, string cmdLine = null, string workDir = null, bool visible = true)
        {
            var hUserToken = IntPtr.Zero;
            var startInfo = new STARTUPINFO();
            var procInfo = new PROCESS_INFORMATION();
            var pEnv = IntPtr.Zero;
            int iResultOfCreateProcessAsUser;

            startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));

            try
            {
                if (!GetSessionUserToken(ref hUserToken))
                {
                    throw new Exception("StartProcessAsCurrentUser: GetSessionUserToken failed.");
                }

                uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                startInfo.lpDesktop = "winsta0\\default";

                if (!CreateEnvironmentBlock(ref pEnv, hUserToken, false))
                {
                    throw new Exception("StartProcessAsCurrentUser: CreateEnvironmentBlock failed.");
                }

                if (!CreateProcessAsUser(hUserToken,
                    appPath, // Application Name
                    cmdLine, // Command Line
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    dwCreationFlags,
                    pEnv,
                    workDir, // Working directory
                    ref startInfo,
                    out procInfo))
                {
                    iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
                    throw new Exception("StartProcessAsCurrentUser: CreateProcessAsUser failed.  Error Code -" + iResultOfCreateProcessAsUser);
                }

                iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
            }
            finally
            {
                CloseHandle(hUserToken);
                if (pEnv != IntPtr.Zero)
                {
                    DestroyEnvironmentBlock(pEnv);
                }
                CloseHandle(procInfo.hThread);
                CloseHandle(procInfo.hProcess);
            }

            return true;
        }

    }
}
"@ 
    # Load the custom type
    try{
        Add-Type -ReferencedAssemblies 'System', 'System.Runtime.InteropServices' -TypeDefinition $Source -Language CSharp -ErrorAction Stop
        Write-OGLogEntry "Attempting to launch:' $FilePath'$(if ($Arguments){" with Argument: '$($Arguments)'"}) as current logged on user."
        # Run PS as user to display the message box
        [Runasuser.ProcessExtensions]::StartProcessAsCurrentUser("$env:windir\System32\WindowsPowerShell\v1.0\Powershell.exe", " -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$FilePath`" $Arguments") | Out-Null
        Write-OGLogEntry "Success launching:' $FilePath'$(if ($Arguments){" with Argument: '$($Arguments)'"}) as current logged on user."
    }
    catch{
        $message = "Failed launching:' $FilePath'$(if ($Arguments){" with Argument: '$($Arguments)'"}) as current logged on user. Error: $_"
        Write-OGLogEntry $message -logtype Error
        throw $message
    }
}


<#
.SYNOPSIS
Test if OneDrive Known Folder Move Enabled for user.

.DESCRIPTION
Test if OneDrive Known Folder Move Enabled for user.

.PARAMETER LoggedOnUser
PS Object retrived for the Get-OGLoggedOnUserCombined function.

.EXAMPLE
Get-OGOneDriveKFMState -LoggedOnUser $LoggedOnUse

.NOTES
    Name:       Get-OGOneDriveKFMState       
	Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-01-25
    Updated:    -
#>
function Get-OGOneDriveKFMState {
    param(
        [parameter(Mandatory = $true, Position = 0,ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$LoggedOnUser
    )
    Write-OGLogEntry "Getting OneDrive KFM state for [User: $($LoggedOnUser.USERNAME)]"
    $OneDriveAcPath = "Software\Microsoft\OneDrive\Accounts"
    $Shell_reg = "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    if(!(Get-PSDrive | Where-Object {$_.Name -eq "HKU"})){New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null}
    $UserOneDriveAcPath = "HKU:\$($LoggedOnUser.SID)\$($OneDriveAcPath)"
    $UserShellPath = "HKU:\$($LoggedOnUser.SID)\$($Shell_reg)"
    $OneDriveBusinessPaths = Get-ChildItem -Path "$($UserOneDriveAcPath)" | Where-Object { ($_.PSIsContainer)-and($_.Name -like "*Business*") } | Select-Object Name
    if ($OneDriveBusinessPaths){
        Write-OGLogEntry "Found OneDrive Business Key [User: $($LoggedOnUser.USERNAME)]"
        foreach ($path in $OneDriveBusinessPaths) {
            $OnedriveData = Get-OGRegistryKey -RegKey "$(($path.Name).Replace('HKEY_USERS','HKU:'))"
            if ($OnedriveData.KFMState){
                Write-OGLogEntry "KFMState is set returning values."
                $OneDriveKFMState = $OnedriveData.KFMState | ConvertFrom-Json
                foreach($p in $OneDriveKFMState.PSObject.Properties){ 
                    if ($p.Value -like "$($LoggedOnUser.USERPROFILE)*"){
                        return $OneDriveKFMState
                    }
                }
            }
            Write-OGLogEntry "OneDrive KFMState property not found @ [Key: $(($path.Name).Replace('HKEY_USERS','HKU:'))]"
        }
        Write-OGLogEntry "OneDrive KFMState not set for [User: $($LoggedOnUser.USERNAME)][Mail:$($LoggedOnUser.Email)]"
        Write-OGLogEntry "Checking User Shell Paths [Path: $($UserShellPath)]"
        $UserShellPaths = Get-ItemProperty -Path "$($UserShellPath)" -ErrorAction SilentlyContinue
        if ($UserShellPaths.Desktop -like "*OneDrive*"){
            Write-OGLogEntry "User's desktop Shell Path is pointing to OneDrive [Path: $($UserShellPaths.Desktop)]"
            Write-OGLogEntry "OneDrive KFMState considered enabled. Returning desktop path."
            $OneDriveDesktopPath = [PSCustomObject]@{
                Desktop = "$($UserShellPaths.Desktop)"
            }
            return $OneDriveDesktopPath
        }
        else{
            Write-OGLogEntry "User's desktop Shell Path does not point to OneDrive [Path: $($UserShellPaths.Desktop)]"
            return $false
        }
    }
    else{
        Write-OGLogEntry "OneDrive path not found [User: $($LoggedOnUser.USERNAME)][Mail:$($LoggedOnUser.Email)][Path: $($UserOneDriveAcPath)"
        return $false
    }
}



<#
.SYNOPSIS
Get OneDrive Accounts for User

.DESCRIPTION
Get OneDrive Accounts for Users. If found returns them.

.PARAMETER LoggedOnUser
PS Obj returned from Get-OGLoggedOnUserCombined

.PARAMETER AccountType
Type of account to search registry for.

.EXAMPLE
Get-OGOneDriveAccounts -LoggedOnUser $objLoggedOnUser -AccountType Business
Returns only Business accounts if found.

.EXAMPLE
Get-OGOneDriveAccounts -LoggedOnUser $objLoggedOnUser -AccountType Personal
Returns only Personal accounts if found.

.EXAMPLE
Get-OGOneDriveAccounts -LoggedOnUser $objLoggedOnUser -AccountType Both
Returns either Business or Persona accounts if found.

.NOTES
    Name:       Get-OGOneDriveAccounts       
	Author:     Richie Schuster - SCCMOG.com
    GitHub:     https://github.com/SCCMOG/PS.SCCMOG.TOOLS
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-04-25
    Updated:    -
#>
function Get-OGOneDriveAccounts {
    param(
        [parameter(Mandatory = $true, Position = 0,ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$LoggedOnUser,
        [parameter(Mandatory = $true, Position = 1,ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [validateset("Business", "Personal", "Both")]
        [PSCustomObject]$AccountType
    )
    $OneDriveAccounts = @()
    $LoggedOnUser = $objLoggedOnUser
    Write-OGLogEntry "Getting OneDrive Accounts for [User: $($LoggedOnUser.USERNAME)]"
    $OneDriveAcPath = "Software\Microsoft\OneDrive\Accounts"
    if(!(Get-PSDrive | Where-Object {$_.Name -eq "HKU"})){New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null}
    $UserOneDriveAcPath = "HKU:\$($LoggedOnUser.SID)\$($OneDriveAcPath)"
    $OneDriveRegAccounts = Get-ChildItem -Path "$($UserOneDriveAcPath)"
    switch($AccountType){
        "Business"{
            $OneDriveBusinessPaths = $OneDriveRegAccounts  | Where-Object { ($_.PSIsContainer)-and($_.Name -like "*$($AccountType)*") } | Select-Object Name
        }
        "Personal"{
            $OneDriveBusinessPaths = $OneDriveRegAccounts  | Where-Object { ($_.PSIsContainer)-and($_.Name -like "*$($AccountType)*") } | Select-Object Name
        }
        "Both"{
            $OneDriveBusinessPaths = $OneDriveRegAccounts  | Where-Object { ($_.PSIsContainer)-and(($_.Name -like "*Personal*")-or($_.Name -like "*Business*"))} | Select-Object Name
        }
    }
    if (($OneDriveBusinessPaths|Measure-Object).Count -gt 0){
        Write-OGLogEntry "Found OneDrive Business Key [User: $($LoggedOnUser.USERNAME)]"
        foreach ($path in $OneDriveBusinessPaths) { # }
            $OneDriveAc = $null
            $OneDriveAc = Get-OGRegistryKey -RegKey "$(($path.Name).Replace('HKEY_USERS','HKU:'))"
            if ((Test-Path -Path "$($OneDriveAc.UserFolder)" -PathType Container)-and($OneDriveAc.UserEmail)){
                Write-OGLogEntry "Found Business Account [Name: $($OneDriveAc.DisplayName)] [Path: $($OneDriveAc.UserFolder)]"
                $OneDriveAccounts += $OneDriveAc
                # foreach($p in $OneDriveKFMState.PSObject.Properties){ 
                #     if ($p.Value -like "$($LoggedOnUser.USERPROFILE)*"){
                #         return $OneDriveKFMState
                #     }
                # }
            }
            else{
                Write-OGLogEntry "OneDrive Account Path invalid [Path: $($OneDriveAc.UserFolder)]" -logtype Warning
            }
        }
        if (($OneDriveAccounts|Measure-Object).Count -gt 0){
            return $OneDriveAccounts
        }

    }
    return $false
}


<#
.SYNOPSIS
Creates a new local Admin account.

.DESCRIPTION
Creates a new local Admin account.

.PARAMETER Account_Name
Name of new local admin account

.PARAMETER PT_Pass
Plain text password.

.PARAMETER Description
Description for account

.EXAMPLE
New-OGLocalAdmin -Account_Name $LocalAdmin -PT_Pass $Password -Description "APM - Get out of Jail Free Account"

.EXAMPLE
New-OGLocalAdmin -Account_Name $LocalAdmin -PT_Pass $Password

.NOTES
    Name:       New-OGLocalAdmin
    Author:     Richie Schuster - SCCMOG.com
    Original:   https://www.scriptinglibrary.com/languages/powershell/create-a-local-admin-account-with-powershell/
    Website:    https://www.sccmog.com
    Contact:    @RichieJSY
    Created:    2022-03-07
    Updated:    -

    Version history:
        1.0.0 - 2022-03-07 Function created
#>
function New-OGLocalAdmin {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Account_Name,
        [Parameter(Mandatory = $true)]
        [string]$PT_Pass,
        [Parameter(Mandatory = $false)]
        [string]$Description = "Temp Local Admin"
    )
    try{
        $sPass = ConvertTo-SecureString -String $PT_Pass -AsPlainText -Force
        New-LocalUser "$Account_Name" -Password $sPass -FullName "$Account_Name" -Description $Description -AccountNeverExpires -PasswordNeverExpires
        Add-LocalGroupMember -Group "Administrators" -Member "$Account_Name"
    }
    catch{
        Write-OGLogEntry "Failed creating local admin. Error: $_"
        return $false
    }
}

##################################################################################################################################
# End Current User Region
##################################################################################################################################

#Get-ChildItem function: | Where-Object { ($currentFunctions -notcontains $_)-and($_.Name -like "*-OG*") } | Select-Object -ExpandProperty name
$Export = @(
    "Get-OGLoggedOnUser",
    "Invoke-OGStartProcessAsCurrentUser",
    "Get-OGLoggedOnUserWMI",
    "Get-OGLoggedOnUserCombined",
    "Get-OGOneDriveKFMState",
    "New-OGLocalAdmin",
    "Get-OGOneDriveAccounts"
)

foreach ($module in $Export){
    Export-ModuleMember $module
}