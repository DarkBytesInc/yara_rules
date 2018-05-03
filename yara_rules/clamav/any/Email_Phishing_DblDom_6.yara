rule Email_Phishing_DblDom_6
{
strings:
	$a0 = { 687474703a2f2f62616e6b696e67706f7274616c2e737061726b617373652e64652e }

condition:
	$a0
}

        
