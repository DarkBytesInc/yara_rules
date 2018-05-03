rule Html_Phishing_Bank_939
{
strings:
	$a0 = { 696e7465726e657462616e6b69676e2d73756e632e636f6d }

condition:
	$a0
}

        
