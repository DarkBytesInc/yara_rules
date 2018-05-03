rule Email_Phishing_DblDom_81
{
strings:
	$a0 = { 687474703a2f2f7777772e737061726b617373652e64652e }

condition:
	$a0
}

        
