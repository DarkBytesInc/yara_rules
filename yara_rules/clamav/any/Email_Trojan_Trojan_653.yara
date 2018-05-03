rule Email_Trojan_Trojan_653
{
strings:
	$a0 = { 2f706f7374636172642e6769662e65786522207461726765743d5f626c616e6b3e687474703a }

condition:
	$a0
}

        
