rule Email_Phishing_Bank_918
{
strings:
	$a0 = { 7a61722f7777772e6e65772e6567672e636f6d2f4c6f6769 }

condition:
	$a0
}

        
