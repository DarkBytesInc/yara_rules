rule Email_Phishing_DblDom_92
{
strings:
	$a0 = { 687474703a2f2f[0-10]2e636f6d6d657263656f6e6c696e652e636f6d2e }

condition:
	$a0
}

        
