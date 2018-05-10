rule PowershellCcDns {
    meta:
    author = "FDD"
    description = "Rule for Powershell bot detection (C2 over DNS queries)"
    severity = "7"
    type = "Exploit Kit"
  strings:
	$Start = "iex" nocase
	$DNS = /nslookup -q=txt [\w.]+/ nocase
  condition:
	all of them
}
