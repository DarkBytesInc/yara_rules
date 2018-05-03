rule Email_Trojan_Phishing_9
{
strings:
	$a0 = { 3d334427687474703a2f2f716c636f2e666173742d6d616e2e636f6d }

condition:
	$a0
}

        
