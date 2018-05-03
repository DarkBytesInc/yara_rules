rule Email_Phishing_DblDom_25
{
strings:
	$a0 = { 687474703a2f2f736572766963652e62616e6b6f66616d65726963612e636f6d2e }

condition:
	$a0
}

        
