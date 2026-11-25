# sysinfo.ps1
$os   = Get-CimInstance Win32_OperatingSystem
$cpu  = Get-CimInstance Win32_Processor
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"

Write-Host "=== System Information ===" -ForegroundColor Cyan
Write-Host "OS:        $($os.Caption) $($os.Version)"
Write-Host "Computer:  $env:COMPUTERNAME"
Write-Host "User:      $env:USERNAME"
Write-Host "CPU:       $($cpu.Name)"
Write-Host "C: Free    $([math]::Round($disk.FreeSpace/1GB,2)) GB of $([math]::Round($disk.Size/1GB,2)) GB"