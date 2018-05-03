rule Email_Phishing_Pay_268
{
strings:
	$a0 = { 31392f2e72656469726563742e70617970616c2e636f6d2f6367692d62696e2f223e0a }

condition:
	$a0
}

        
