rule ApplockerBypass {
    meta:
    author = "Jurriaan Bremer"
    description = "Powershell AppLocker Bypass"
    severity = "5"
    type = "Unknown"
  strings:
    $cmdline = /regsvr32[^;]+\/i:(https?|ftp):\/\/[^\s\/$.?#].[^\s\"']+[\s]+\w+\.dll/
  condition:
	all of them
}
