rule Email_Phishing_DblDom_96
{
strings:
	$a0 = { 687474703a2f2f627573696e6573732d696e7465726e65742d62616e6b696e672e687362632e636f6d2e }

condition:
	$a0
}

        
