rule Win_Trojan_Redir_16
{
strings:
	$a0 = { 3c736372697074207372633d687474703a2f2f73746174736d792e636f6d2f75722e7068703e }

condition:
	$a0
}

        
