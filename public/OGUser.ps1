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
##################################################################################################################################
# End Current User Region
##################################################################################################################################

#Get-ChildItem function: | Where-Object { ($currentFunctions -notcontains $_)-and($_.Name -like "*-OG*") } | Select-Object -ExpandProperty name
$Export = @(
    "Get-OGLoggedOnUser",
    "Invoke-OGStartProcessAsCurrentUser"
)

foreach ($module in $Export){
    Export-ModuleMember $module
}