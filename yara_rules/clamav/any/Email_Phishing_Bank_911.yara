rule Email_Phishing_Bank_911
{
strings:
	$a0 = { 6f72657830362e636f6d2f636f6c6170706d67722f636f6c706f72 }

condition:
	$a0
}

        
