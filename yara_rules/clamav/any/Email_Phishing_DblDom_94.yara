rule Email_Phishing_DblDom_94
{
strings:
	$a0 = { 687474703a2f2f76722d6e6574776f726c642e64652e }

condition:
	$a0
}

        
