rule Email_Phishing_DblDom_34
{
strings:
	$a0 = { 687474703a2f2f737061726b617373652e61742e }

condition:
	$a0
}

        
