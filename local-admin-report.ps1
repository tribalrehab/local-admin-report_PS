# setup script path
$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
Set-Location $scriptDir
# --- optional / use AD for computer objects vs SNOW API
#write-output "Querying Active Directory ..."
#$servers = Get-ADComputer -SearchBase "OU=Windows Servers,DC=corp,DC=domain,DC=com" -Filter 'operatingsystem -like "*windows*" -and enabled -eq "true"' -Properties Name,operatingsystem
Write-Output "Querying ServiceNOW CMDB ..."
$request = Invoke-RestMethod -Uri "https://corp.service-now.com/api/now/cmdb/instance/cmdb_ci?sysparm_query=dns_domain=corp.domain.com^install_status=1&sysparm_limit=10000" -Method Get -ContentType "application/json"
Write-Output "Found: $($request.result.count) objects"
Start-Sleep -Seconds 5
# setup arraylists for server objects
$servers = New-Object System.Collections.ArrayList
$remediate = New-Object System.Collections.ArrayList

# used for compatibility between ad/servicenow api query
foreach ($itm in $request.result) {
	$servers.Add($itm.Name) | Out-Null
}
# clear cache
$path = "$($ScriptDir)\servers"
Remove-Item "$scriptpath\servers" -Filter *.txt -Force -Recurse -Confirm:$false
# create cache folder if it doesn't exist
if (!(Test-Path $path)) {
	New-Item -ItemType Directory -Force -Path $path
}
# begin looping through each server to query
$i = 0
foreach ($server in $servers) {
	Clear-Host
	$i++
	$jobcomputername = $server
	try {
		$os = (Get-ADComputer -Identity $server -Properties operatingsystem).operatingsystem
	} catch {
		$os = "Not Found in AD"
	}

	# filter our bad object names
	if ($jobcomputername -like "*:*") {
		continue
	}
	# skip servers in the cache 
	if (Test-Path "$($ScriptDir)\servers\$($jobcomputername).txt") {
		continue
	}

	# begin the WINRM query
	Write-Output "Running Local Admin Group Query (WINRM)"
	Write-Output "--------------------------------------"
	Write-Output ""
	Write-Output "Executing $($i)/$($servers.Count)"
	Write-Output ""
	# loop through each job and remove any completed jobs
	foreach ($j in Get-Job) {
		if ($j.state -eq "Completed") {
			$report = Receive-Job -Id $j.Id
			if ($report -eq "" -or $report -eq " " -or $report -eq $null) {
				"FAILED" | Out-File "$($ScriptDir)\servers\$($j.Name).txt" -Force
			} else {
				$report | Out-File "$($ScriptDir)\servers\$($j.Name).txt" -Force
			}
			Remove-Job -Id $j.Id
		}
	}
	# set job maximum at 20 jobs
	Get-Job
	Start-Sleep -Milliseconds 100
	while ($(Get-Job -State running).count -ge 20) {
		Start-Sleep -Milliseconds 50
	}

	$job = Start-Job -Name $jobcomputername -ArgumentList $jobcomputername,$os -ScriptBlock {
		$computername = $args[0]
		$os = $args[1]
		# code that gets executed locally
		$winrm_block = {
			$computername = $args[0]
			$os = $args[1]
			$group = [adsi]"WinNT://./Administrators"
			$members = @($group.Invoke("Members"))

			foreach ($member in $members) {
				try {
					$MemberName = $member.GetType().InvokeMember("Name","GetProperty",$null,$member,$null)
					$MemberType = $member.GetType().InvokeMember("Class","GetProperty",$null,$member,$null)
					$MemberPath = $member.GetType().InvokeMember("ADSPath","GetProperty",$null,$member,$null)
					$MemberDomain = $null
					if ($MemberPath -match "^Winnt\:\/\/(?<domainName>\S+)\/(?<CompName>\S+)\/") {
						if ($MemberType -eq "User") {
							$MemberType = "LocalUser"
						} elseif ($MemberType -eq "Group") {
							$MemberType = "LocalGroup"
						}
						$MemberDomain = $matches["CompName"]
					} elseif ($MemberPath -match "^WinNT\:\/\/(?<domainname>\S+)/") {
						if ($MemberType -eq "User") {
							$MemberType = "DomainUser"
						} elseif ($MemberType -eq "Group") {
							$MemberType = "DomainGroup"
						}
						$MemberDomain = $matches["domainname"]
					} else {
						$MemberType = "LocalAccount/Bad SID"
						$MemberDomain = "LocalAccount"
					}
					# return the data from the job
					Write-Output "$($computername),Administrators,$MemberType,$MemberDomain,$MemberName,$os"
				} catch {
					# this is a failure to query the local groups
					Write-Output "$($args[0]),,FailedQueryMember"
					$write = 0
				}
			}
		}
		try {
			Invoke-Command -ComputerName $computername -ArgumentList $computername,$os -ScriptBlock $winrm_block -ErrorAction SilentlyContinue
		} catch {
			"FAILED" | Out-File "$($ScriptDir)\servers\$($computername).txt" -Force
			$winrm_fail = 1
		}
	}

	$job | Receive-Job -Keep

}
# WinRM Query is completed, begin checking against failures and query those failed machines with WMI
Clear-Host
Write-Host "Cleaning up finished Jobs ..." -ForegroundColor Yellow
$jobscleanup = Get-Job
$jcount = 0
Write-Host "Jobs Found: $($jobscleanup.count)"
while (!(Get-Job).count -eq 0) {
	foreach ($j in Get-Job) {
		if ($jcount -gt 10) {
			$jcount = 0
			Remove-Job -Id $j.Id -Force
		}
		if ($j.state -eq "Completed") {
			Write-Host "   -Cleared JOB $($j.Name)" -ForegroundColor DarkGray
			$report = Receive-Job -Id $j.Id
			$report | Out-File "$($ScriptDir)\servers\$($j.Name).txt" -Force
			Remove-Job -Id $j.Id
		}
	}
	Start-Sleep -Seconds 20
	$jcount++
	Write-Output "Job Timeout: $($jcount) / 20"
}
Write-Host "Done!"

# failback on wmi
$i = 0
$returnstring = ""
$JobLocalGroupName = "Administrators"
foreach ($server in $servers) {
	$i++
	$JobComputerName = $server
	$write = 1
	if (Test-Path "$($path)\$($jobcomputername).txt") {
		$tmp = Get-Content "$($path)\$($jobcomputername).txt"
		if ($tmp -like "*offline*" -or $tmp -like "*FailedToQuery*" -or $tmp -like "*NoMembersFound*" -or $tmp -like "*FailedQueryMember*" -or $tmp -eq "FAILED" -or $tmp -like "*FAILED*") {
		} else { continue }
	}
	Write-Output "Running Local Admin Group Query (WMI)"
	Write-Output "-------------------------------------"
	Write-Output ""
	Write-Output "Executing $($i)/$($servers.Count)"
	Write-Output ""
	foreach ($j in Get-Job) {
		if ($j.state -eq "Completed") {
			Remove-Job -Id $j.Id
		}
	}
	# set job maximum at 20 jobs
	Get-Job
	Start-Sleep -Milliseconds 100
	while ($(Get-Job -State running).count -ge 20) {
		Start-Sleep -Milliseconds 50
	}

	$job = Start-Job -ArgumentList $JobComputerName,$JobLocalGroupName,$path,$os -Name $JobComputerName -ScriptBlock {
		# Initiate Connection
		if (!(Test-Connection -ComputerName $args[0] -Count 1 -Quiet)) {
			# Ping FAILED
			Write-Host "Offline" -ForegroundColor Yellow
			$returnstring += "$($args[0]),,offline`r`n"
			$write = 1
		} else {
			# Attempt connection via WMI
			Write-Host "OK!" -ForegroundColor green
			Write-Host "Attemping WMI Connection ... " -NoNewline
			try {
				$group = [adsi]"WinNT://$($args[0])/$($args[1])"
				Write-Host "OK!" -ForegroundColor green
				Write-Host "Enumerating Group [$($localgroup)] Members ... " -NoNewline
				$members = @($group.Invoke("Members"))
				if (!$members) {
					Write-Host "EMPTY!" -ForegroundColor yellow
					$returnstring += "$($args[0]),$($args[1]),NoMembersFound`r`n"
					$write = 1
					continue
				}
			} catch {
				# WMI FAILED
				$returnstring += "$($args[0]),,FailedToQuery`r`n"
				Write-Host "Failed!" -ForegroundColor Yellow
				$write = 1
			}
			Write-Host "Done!" -ForegroundColor green
			foreach ($member in $members) {
				try {
					$MemberName = $member.GetType().InvokeMember("Name","GetProperty",$null,$member,$null)
					$MemberType = $member.GetType().InvokeMember("Class","GetProperty",$null,$member,$null)
					$MemberPath = $member.GetType().InvokeMember("ADSPath","GetProperty",$null,$member,$null)
					$MemberDomain = $null
					if ($MemberPath -match "^Winnt\:\/\/(?<domainName>\S+)\/(?<CompName>\S+)\/") {
						if ($MemberType -eq "User") {
							$MemberType = "LocalUser"
						} elseif ($MemberType -eq "Group") {
							$MemberType = "LocalGroup"
						}
						$MemberDomain = $matches["CompName"]

					} elseif ($MemberPath -match "^WinNT\:\/\/(?<domainname>\S+)/") {
						if ($MemberType -eq "User") {
							$MemberType = "DomainUser"
						} elseif ($MemberType -eq "Group") {
							$MemberType = "DomainGroup"
						}

						$MemberDomain = $matches["domainname"]

					} else {
						$MemberType = "Unknown"
						$MemberDomain = "Unknown"
					}
					$ReturnString += "$($args[0]),$($args[1]),$MemberType,$MemberDomain,$MemberName,$($args[3])`r`n"
				} catch {
					$ReturnString += "$($args[0]),,FailedQueryMember`r`n"
					$write = 0
				}
			}
		}
		if ($write -eq 1) {
			$returnstring | Out-File -FilePath "$($args[2])\$($args[0]).txt" -Force
		}
	}

	$job | Receive-Job -Keep
	Clear-Host
}

# generate report
Write-Host "Generating Report ... " -ForegroundColor Yellow -NoNewline
$files = Get-ChildItem $path -Filter *.txt
"File,Server Name,Group,Member Type,Group Location,Member,Operating System" | Out-File "report.csv" #-Append
foreach ($file in $files) {
	$content = Get-Content "$($path)\$($file)"
	foreach ($c in $content) {
		if ($c -ne "") {
			"$($file.name),$($c)" | Out-File "report.csv" -Append
		}
	}
}

# Compliance Report
# Counters

$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
Set-Location $scriptDir
$path = "$($ScriptDir)\servers"
$files = Get-ChildItem $path -Filter *.txt
$counter_servers = $files.count
Remove-Item remediate.txt -Force

$counter_sid = 0
$counter_offline = 0
$counter_wmifailure = 0
$counter_wmi_rm = 0
$counter_os_win10 = 0
$counter_os_server2008 = 0
$counter_os_server2012 = 0
$counter_os_server2016 = 0
$remediate.Clear()

foreach ($file in $files) {
	$content = Get-Content "$($path)\$($file.name)"
	if ($content -like "*offline*") {

		$counter_offline++
		$rem = $file.Name -replace ".txt",""
		$remediate.Add($rem)
	}
	if ($content -like "*FailedToQuery*") {
		$counter_wmifailure++
		$rem = $file.Name -replace ".txt",""
		$remediate.Add($rem)
	}
	if ($content -like "*FAILED*") {
		$counter_wmi_rm++
		$rem = $file.Name -replace ".txt",""
		$remediate.Add($rem)
	}
	if ($content -like "*S-1*") {
		$counter_sid++
	}
	if ($content -like "*Windows 10*") {
		$counter_os_win10++
	}
	if ($content -like "*Windows Server 2008*") {
		$counter_os_server2008++
	}
	if ($content -like "*Windows Server 2012*") {
		$counter_os_server2012++
	}
	if ($content -like "*Windows Server 2016*") {
		$counter_os_server2016++
	}
}

# write the final report
$csv = Import-Csv "$($ScriptDir)\report.csv"
$report_critical = New-Object -TypeName "System.Collections.ArrayList"
$report_sid = New-Object -TypeName "System.Collections.ArrayList"
foreach ($line in $csv) {

	# Critical
	if ($line. 'Member Type' -eq "DomainUser") {
		if ($line.Member -notlike "*admon*") {
			if ($line.Member -notlike "*z_*") {
				if ($line.Member -notlike "*$*") {
					$report_critical.Add("$($line.'Server Name');$($line.Member);$($line.'Operating System')") | Out-Null
				}
			}
		}
	}

	# Warning/SID
	if ($line. 'Member Type' -eq "Unknown") {
		if ($line.Member -like "*S-1*") {
			$report_sid.Add("$($line.'Server Name');$($line.Member);$($line.'Operating System')") | Out-Null
		}
	}
}

# start generating the HTML report
Write-Output "Total Server: $($counter_servers)"
Write-Output "Total Offline: $($counter_offline)"
Write-Output "WMI Failure: $($counter_wmifailure)"
Write-Output "WINRM/WMI Failure: $($counter_wmi_rm)"
Write-Output "Invalid SIDS: $($counter_sid)"

# begin html code
$html = "<html><body bgcolor='#d1d1d1'>"
$html1 = "<html><body bgcolor='#d1d1d1'>"

# Total Servers
$html += "<table border=0 cellspacing=10 cellpadding=10><tr>"
$html += "<td bgcolor=#ededed><center><font face=arial size=3>Total Number of Windows Servers<br><br></font><font face=arial size=5>$($counter_servers)<br><br></font></td>"
$html += "<td bgcolor=#ededed><center><font face=arial size=3>Total Unreachable<br><br></font><font face=arial size=5>$($counter_offline)<br><br></font></td>"
$html += "<td bgcolor=#ededed><center><font face=arial size=3>Servers with WMI Failure<br><br></font><font face=arial size=5>$($counter_wmifailure)<br><br></font></td>"
$html += "<td bgcolor=#ededed><center><font face=arial size=3>Servers with WMI & WINRM Failure<br><br></font><font face=arial size=5>$($counter_wmi_rm)<br><br></font></td>"
$html += "<td bgcolor=#ededed><center><font face=arial size=3>Number of Invalid SIDS<br><br></font><font face=arial size=5>$($counter_sid)<br><br></font></td>"
$html += "</tr></table>"
$html += "<table border=0 cellspacing=10 cellpadding=10><tr>"
$html += "<td bgcolor=#ededed><center><font face=arial size=3>Operating Systems by OS (Online)<br><br></font><font face=arial size=5>
<table border=0 width=100%><tr><td><font size=-1 face=arial>Operating System</td><td><font size=-1 face=arial>Count</td><td><font size=-1 face=arial>Percentage</td></tr>
<td><font size=-1 face=arial>Windows 10</td><td><font size=-1 face=arial>$($counter_os_win10)</td><td><font size=-1 face=arial>$(($counter_os_win10/$counter_servers).tostring("P"))</td></tr><tr>
<td><font size=-1 face=arial>Windows 2008</td><td><font size=-1 face=arial>$($counter_os_server2008)</td><td><font size=-1 face=arial>$(($counter_os_server2008/$counter_servers).tostring("P"))</td></tr><tr>
<td><font size=-1 face=arial>Windows 2012</td><td><font size=-1 face=arial>$($counter_os_server2012)</td><td><font size=-1 face=arial>$(($counter_os_server2012/$counter_servers).tostring("P"))</td></tr><tr>
<td><font size=-1 face=arial>Windows 2016</td><td><font size=-1 face=arial>$($counter_os_server2016)</td><td><font size=-1 face=arial>$(($counter_os_server2016/$counter_servers).tostring("P"))</td></tr></table>
<br></font></td>"
$html += "</tr></table>"


# Critical Report
$html += "<table border=0 cellspacing=5 cellpadding=5 width=70%><tr><td><font size=4 face=arial>Accounts with Direct Membership<br>"
$html += "<table border=0 cellspacing=10 cellpadding=10 bgcolor=#ededed width=100%><tr><td><b><font face=arial>Server Name</td><td><b><font face=arial>Admin User</td><td><b><font face=arial>Operating System</td></tr>"
foreach ($item in $report_critical) {
	$item1 = $item -split ";"
	$html += "<tr><td><font face=arial>$($item1[0])</td><td><font face=arial>$($item1[1])</td><td><font face=arial>$($item1[2])</td></tr>"
}
$html += "</table><br><br>"

# Invalid SIDS Report
$html += "</table><table border=0 cellspacing=5 cellpadding=5 width=70%><tr><td><font size=4 face=arial>Group Membership With Invalid SIDS<br>"

$html += "<table border=0 cellspacing=10 cellpadding=10 bgcolor=#ededed width=100%><tr><td><b><font face=arial>Server Name</td><td><b><font face=arial>Admin User</td><td><b><font face=arial>Operating System</td></tr>"
foreach ($item in $report_sid) {
	$item1 = $item -split ";"
	$html += "<tr><td><font face=arial>$($item1[0])</td><td><font face=arial>$($item1[1])</td><td><font face=arial>$($item1[2])</td></tr>"
}
$html += "</table>"

# Remediate Report
$html1 += "</table><table border=0 cellspacing=5 cellpadding=5 width=70%><tr><td><font size=4 face=arial>Offline Server List to Remediate<br>"
$html1 += "<table border=0 cellspacing=10 cellpadding=10 bgcolor=#ededed width=100%><tr><td><b><font face=arial>Server Name</td></tr>"
foreach ($rem_item in $remediate) {

	$html1 += "<tr><td><font face=arial>$($rem_item)</td></tr>"
}
$html1 += "</table>"
$html += "</td></tr></html>"

$html | Out-File "report.html"
$html1 | Out-File "remediate.html"
$to = "DL@domain.com"
[string[]]$to = $to.split(',')

Send-MailMessage –From report@domain.com –to $to –Subject "Local Admin Compliance Report" -BodyAsHtml -Body $html –smtpserver smtpserver –Attachments report.csv
Send-MailMessage –From report@domain.com –to $to –Subject "Offline Windows Server (Remediation Required)" -BodyAsHtml -Body $html1 –smtpserver smtpserver –Attachments report.csv

Write-Host "Done!"
