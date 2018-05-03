rule Html_Phishing_Bank_917
{
strings:
	$a0 = { 2e69676f74667265652e636f6d2f63686173655f66756c6c696e666f2f22200a203e68747470733a2f2f }

condition:
	$a0
}

        
