# script is useful for gathering host information - Red Teaming

$banner = $banner + "`r`n"
$banner = $banner + "`r`n"
$banner = $banner + "`r`n"
$banner = $banner + "||==========================================================================||`r`n"
$banner = $banner + "||---------------- Script written by Ch33t@h - Vardan Bansal ---------------||`r`n"
$banner = $banner + "||--------------------------------------------------------------------------||`r`n"
$banner = $banner + "||--------------------------------------------------------------------------||`r`n"
$banner = $banner + "||--------------------------- Host Enumeration -----------------------------||`r`n"
$banner = $banner + "||--------------------------------------------------------------------------||`r`n"
$banner = $banner + "||----------------------------  Red Teaming --------------------------------||`r`n"
$banner = $banner + "||==========================================================================||`r`n"

write-output $banner

$date = $date + "`r`n"
$date = Get-Date
write-output "-------------- ran this script on $date ----------"

write-output ""
write-output "------------------- Get Defender Status ---------------------"
$defender = $defender + "`r`n"
$defender = Get-MpComputerStatus
write-output $defender

write-output ""
write-output "------------------- Get Computer Information ---------------------"
$computer = systeminfo
write-output $computer

write-output ""
write-output "------------------- Get Network Information ---------------------"
$network = ipconfig
write-output $network

write-output ""
write-output "------------------- Get Active connection Information ---------------------"
$connection = netstat -ano
write-output $connection

write-output ""
write-output "------------------- Get Address resolution protocol Information ---------------------"
$arp = arp -a
write-output $arp


write-output ""
write-output "------------------- Get Host files content ---------------------"
$hostFiles = (get-content $env:windir\System32\drivers\etc\hosts | out-string)
write-output $hostFiles

write-output ""
write-output "------------------- Gathering processes ---------------------"
$process = ((Get-WmiObject win32_process | Select-Object Name,ProcessID,@{n='Owner';e={$_.GetOwner().User}},CommandLine | sort name | format-table -wrap -autosize))
write-output $process

write-output ""
write-output "------------------- services ---------------------"
$service = Get-Service
write-output $service

write-output ""
write-output "------------------- scheduled task ---------------------"
$schTask = (schtasks /query /FO CSV /v | convertfrom-csv | where { $_.TaskName -ne "TaskName" } | select "TaskName","Run As User", "Task to Run"  | fl)
write-output $schtasks

write-output ""
write-output "------------------- Gathering installed software ---------------------"
$installSoftware = (get-wmiobject -Class win32_product | select Name, Version, Caption | ft -hidetableheaders -autosize| out-string -Width 4096)
write-output = $installSoftware

write-output ""
write-output "------------------- Program files ---------------------"
$programFiles = get-childitem "C:\Program Files" |select Name |ft -HideTableHeaders
write-output $programFiles

write-output ""
write-output "------------------- Program files (x86) ---------------------"
$programFilesX86 = get-childitem "C:\Program Files (x86)" |select Name |ft -HideTableHeaders
write-output $programFilesX86

write-output ""
write-output "------------------- Mapped drive ----------------------"
$mappedDrive = (Get-WmiObject -Class Win32_LogicalDisk | select DeviceID, VolumeName | ft -hidetableheaders -autosize | out-string -Width 4096)
write-output $mappedDrive

write-output ""
write-output "------------------- Unquotted service path ---------------------"
$unquottedPath = (cmd /c  'wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """')
write-output $unquottedPath


write-output ""
write-output "------------------- Recent Documents ---------------------"
$recentDoc = (get-childitem "C:\Users\$env:username\AppData\Roaming\Microsoft\Windows\Recent" | select Name | ft -hidetableheaders )
write-output $recentDoc

write-output ""
write-output "------------------- Interesting files in users directory ---------------------"
$interestingFiles = (get-childitem "C:\Users\" -recurse -Include *.zip,*.rar,*.7z,*.gz,*.conf,*.rdp,*.kdbx,*.crt,*.pem,*.ppk,*.txt,*.xml,*.vnc.*.ini,*.vbs,*.bat,*.ps1,*.cmd -EA SilentlyContinue | %{$_.FullName } | out-string)
write-output $interestingFiles


write-output ""
write-output "------------------- Top 20 modified files ---------------------"
$modifiedItems = (Get-ChildItem 'C:\Users' -recurse | Sort {$_.LastWriteTime} |  %{$_.FullName } | select -last 25 | ft -hidetableheaders | out-string)
write-output $modifiedItems

write-output ""
write-output "------------------- Stored credentials ---------------------"
$storedCred = cmdkey /list 
write-output $storedCred

write-output ""
write-output "------------------- Checking for Wifi Passwords ---------------------"
$listProfiles = netsh wlan show profiles | Select-String -Pattern "All User Profile" | %{ ($_ -split ":")[-1].Trim() };
$listProfiles | foreach {
	$profileInfo = netsh wlan show profiles name=$_ key="clear";
	$SSID = $profileInfo | Select-String -Pattern "SSID Name" | %{ ($_ -split ":")[-1].Trim() };
	$Key = $profileInfo | Select-String -Pattern "Key Content" | %{ ($_ -split ":")[-1].Trim() };
	[PSCustomObject]@{
		WifiProfileName = $SSID;
		Password = $Key
	}
}

write-output $listProfiles