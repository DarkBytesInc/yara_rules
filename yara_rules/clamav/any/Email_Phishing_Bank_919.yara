rule Email_Phishing_Bank_919
{
strings:
	$a0 = { 2e756b2f7777772e68616c696661782d6f6e6c696e652e636f2e756b2f5f6d656d5f }

condition:
	$a0
}

        
