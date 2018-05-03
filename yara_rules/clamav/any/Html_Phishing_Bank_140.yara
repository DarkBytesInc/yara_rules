rule Html_Phishing_Bank_140
{
strings:
	$a0 = { 3c6120687265663d22687474703a2f2f6f6e6c696e652e726567696f6e732e636f6d253265 }
	$a1 = { 3c696d67207372633d226369643a }

condition:
	$a0 and $a1
}

        
