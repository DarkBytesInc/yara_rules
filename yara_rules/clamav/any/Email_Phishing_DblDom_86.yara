rule Email_Phishing_DblDom_86
{
strings:
	$a0 = { 687474703a2f2f6962616e6b696e672e737467656f7267652e636f6d2e61752e }

condition:
	$a0
}

        
