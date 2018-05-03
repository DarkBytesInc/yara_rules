rule Email_Phishing_DblDom_93
{
strings:
	$a0 = { 687474703a2f2f766f6c6b7362616e6b2e64652e }

condition:
	$a0
}

        
