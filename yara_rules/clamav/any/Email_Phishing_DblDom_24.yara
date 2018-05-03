rule Email_Phishing_DblDom_24
{
strings:
	$a0 = { 2e6d6f6e65796d616e616765726770732e636f6d2e }

condition:
	$a0
}

        
