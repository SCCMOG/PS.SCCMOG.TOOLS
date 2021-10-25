SCCMOG-Tools Powershell Module

This module is designed to help with deployment.
I am still currently working on it so there will be many changes ahead.

To download and install the module copy and paste the below code into your code editor of choice.
Replace the "scriptRoot" variable string with the root of your script directory and run the code.

```powershell
#Variables
#$scriptRoot = Split-Path $script:MyInvocation.MyCommand.Path #Run from saved script
$scriptRoot = "c:\<YourScriptRoot>"
$ModuleName = "PS.SCCMOG.TOOLS"
$GitOwner = "SCCMOG"
$GitBranch = "main"

#Import PS.SCCMOG.TOOLS
try{
    if (Test-Path "$scriptRoot\$ModuleName" -PathType Container){
        Import-Module "$($scriptRoot)\$($ModuleName)\$($ModuleName).psd1" -Force -Verbose
    }
    Else{      
        Write-Warning "Module: $($ModuleName) not found. Downloading and importing!"
        $url = "https://github.com/$GitOwner/$ModuleName/archive/$GitBranch.zip"
        $output = Join-Path $scriptRoot "$($ModuleName).zip"
        #Get-ChildItem -Path $($scriptRoot) -Filter "$($ModuleName)*" -Directory | Remove-Item -Recurse -Force
        $wc = New-Object System.Net.WebClient;
        $wc.DownloadFile($url, $output)
        $Expanded = Expand-Archive -Path $output -DestinationPath "$($scriptRoot)" -Force
        Get-ChildItem -Path $($scriptRoot) -Filter "$($ModuleName)*" -Directory | Rename-Item -NewName "$($ModuleName)"
        $timeStamp= "[Module: $($ModuleName)][Download_by: $(([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name)][Parent_Script: $(($MyInvocation.MyCommand.Name).Replace('.ps1',''))][Time: $(Get-Date -f 'hh:mm')][Date: $(Get-Date -f 'yyyy-MM-dd')][PID: $($PID)]" `
                         | Out-File "$scriptRoot\ModuleDownload.log" -Append -Force
        Import-Module "$($scriptRoot)\$($ModuleName)\$($ModuleName).psm1" -Force -Verbose
    }
}
catch{
    throw "Failed to import the module $($ModuleName). Error: $_"
}


Write-OGLogEntry -logtype Header
```
