rule Email_Phishing_DblDom_117
{
strings:
	$a0 = { 687474703a2f2f737061726b617373652e64652e }

condition:
	$a0
}

        
