rule Email_Phishing_Bank_910
{
strings:
	$a0 = { 2e636f6d2f6962616e6b2e626172636c6179732e636f2e756b2f4c6f67696e4d656d6265722e646f }

condition:
	$a0
}

        
