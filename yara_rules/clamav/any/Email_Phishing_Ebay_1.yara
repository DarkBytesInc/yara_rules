rule Email_Phishing_Ebay_1
{
strings:
	$a0 = { 687474703a2f2f626e6d626e6d766e76626d6e6d2e396b2e636f6d2f[0-41]6f6668706668662e68746d6c }

condition:
	$a0
}

        
