rule Email_Phishing_Bank_1267
{
strings:
	$a0 = { 7372633d22687474703a2f2f6933372e74696e797069632e636f6d2f7668343567352e6a706722 }

condition:
	$a0
}

        
