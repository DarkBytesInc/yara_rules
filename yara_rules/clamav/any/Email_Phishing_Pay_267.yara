rule Email_Phishing_Pay_267
{
strings:
	$a0 = { 6d6d656e7365652e63682f70617970616c2f696e6465782e6874 }

condition:
	$a0
}

        
