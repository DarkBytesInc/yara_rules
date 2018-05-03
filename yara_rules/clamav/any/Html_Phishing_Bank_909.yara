rule Html_Phishing_Bank_909
{
strings:
	$a0 = { 2f2e7365617273636172642e636f6d2f696e6465782e6a73702e68746d223e }

condition:
	$a0
}

        
