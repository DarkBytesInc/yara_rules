rule Email_Phishing_Bank_914
{
strings:
	$a0 = { 696e2e636f6d2f7777772e776163686f76696162616e6b2e636f6d2f7777772e776163686f7669616261 }

condition:
	$a0
}

        
