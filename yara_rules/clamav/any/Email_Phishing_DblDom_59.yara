rule Email_Phishing_DblDom_59
{
strings:
	$a0 = { 687474703a2f2f7777772e65706f72742e657175696661782e636f6d2e }

condition:
	$a0
}

        
