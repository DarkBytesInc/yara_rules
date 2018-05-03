rule Html_Phishing_Bank_144
{
strings:
	$a0 = { 3c6120687265663d22687474703a2f2f[0-64]2e636f6d3a323830223e3c696d67207372633d226369643a }

condition:
	$a0
}

        
