$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\SentinelView.lnk")
$Shortcut.TargetPath = "C:\SentinelView\START_SENTINEL.bat"
$Shortcut.WorkingDirectory = "C:\SentinelView"
$Shortcut.Description = "SentinelView SIEM+SOAR Platform"
$Shortcut.Save()
Write-Host "Desktop shortcut created successfully"