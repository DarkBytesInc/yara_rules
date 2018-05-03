rule Email_Phishing_DblDom_87
{
strings:
	$a0 = { 687474703a2f2f7777772e6278732e696e766965772e73657373 }

condition:
	$a0
}

        
