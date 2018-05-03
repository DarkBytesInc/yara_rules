rule Html_Phishing_Bank_106
{
strings:
	$a0 = { 3c696d67207372633d226369643a }
	$a1 = { 636f6c6f723d626c75652073697a653d323e687474703a2f2f626172636c6179732e636f2e756b2f }

condition:
	$a0 and $a1
}

        
