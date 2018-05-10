rule Powerfun {
    meta:
    author = "FDD @ Cuckoo Sandbox"
    description = "Rule for the Powefun shellcode injector"
    severity = "7"
    type = "Exploit Kit"
  strings:
	$obj1 = "New-Object System.Diagnostics.ProcessStartInfo" nocase
	$fn1 = "IEX" nocase
	$fn2 = "IO.Compression.GzipStream" nocase
	$fn3 = "[System.Diagnostics.Process]::Start" nocase
	$fn4 = "::Decompress" nocase
	$Shellcode = /FromBase64String\(['"]+[\w=\/\+]+['"]+\)/ nocase
  condition:
	all of them
}
