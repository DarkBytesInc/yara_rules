rule Email_Phishing_Bank_1313
{
strings:
	$a0 = { 49434154494f4e2046524f4d2042414e4b204f46204e4557205a45414c414e44 }
	$a1 = { 626e7a2e636f2e6e7a2e }

condition:
	$a0 and $a1
}

        
