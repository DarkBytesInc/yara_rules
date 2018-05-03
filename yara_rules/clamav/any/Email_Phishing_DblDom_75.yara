rule Email_Phishing_DblDom_75
{
strings:
	$a0 = { 687474703a2f2f627573696e6573732e687362632e636f6d2e }

condition:
	$a0
}

        
