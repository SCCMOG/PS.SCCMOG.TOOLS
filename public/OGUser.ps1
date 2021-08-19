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
function Get-OGLoggedOnUser () {
    Write-OGLogEntry -Logtext "Getting Currently logged on user for machine: $($ENV:COMPUTERNAME)"
    $CurrentLoggedOnUser = $null
    $AllUserCheck = @()
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
Get-OGLoggedOnUser
##################################################################################################################################
# End Current User Region
##################################################################################################################################