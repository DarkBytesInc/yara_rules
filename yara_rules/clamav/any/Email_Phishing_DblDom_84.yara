rule Email_Phishing_DblDom_84
{
strings:
	$a0 = { 687474703a2f2f61647665727469736572732e7365656b2e636f6d2e61752e }

condition:
	$a0
}

        
