rule Email_Phishing_DblDom_78
{
strings:
	$a0 = { 687474703a2f2f76726e6574776f726c642e64652e }

condition:
	$a0
}

        
