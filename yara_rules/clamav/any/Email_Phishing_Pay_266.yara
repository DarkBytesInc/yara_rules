rule Email_Phishing_Pay_266
{
strings:
	$a0 = { 703a2f2f7777772e70617970616c2e636f6d2e762d72 }

condition:
	$a0
}

        
