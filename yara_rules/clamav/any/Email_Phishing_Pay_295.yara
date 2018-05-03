rule Email_Phishing_Pay_295
{
strings:
	$a0 = { 687474703a2f2f353130393131696e666f2e306d6f6f6c612e636f6d2f313134312f7365637572652f }

condition:
	$a0
}

        
