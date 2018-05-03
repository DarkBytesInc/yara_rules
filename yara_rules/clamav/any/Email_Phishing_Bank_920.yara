rule Email_Phishing_Bank_920
{
strings:
	$a0 = { 657462616e6b2e627564617065737462616e6b2e6e65742f6d61 }

condition:
	$a0
}

        
