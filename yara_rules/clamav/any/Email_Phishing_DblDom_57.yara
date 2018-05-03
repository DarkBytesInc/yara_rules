rule Email_Phishing_DblDom_57
{
strings:
	$a0 = { 687474703a2f2f7777772e7961686f6f2e616d65726963616e6772656574696e67732e636f6d2e }

condition:
	$a0
}

        
