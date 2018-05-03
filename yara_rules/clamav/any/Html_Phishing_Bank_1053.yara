rule Html_Phishing_Bank_1053
{
strings:
	$a0 = { 7472652f7777772e62616e6b6f66616d65726963612e636f }

condition:
	$a0
}

        
