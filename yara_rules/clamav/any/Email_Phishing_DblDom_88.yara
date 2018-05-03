rule Email_Phishing_DblDom_88
{
strings:
	$a0 = { 687474703a2f2f7369676e696e2d656261792d636f2d756b2e }

condition:
	$a0
}

        
