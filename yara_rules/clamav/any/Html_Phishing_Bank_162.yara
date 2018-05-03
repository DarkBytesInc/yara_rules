rule Html_Phishing_Bank_162
{
strings:
	$a0 = { 2f2e2e2e2f722f223e3c696d67207372633d226369643a[0-50]40726567696f6e732e636f6d22 }

condition:
	$a0
}

        
