rule Email_Trojan_Phishing_5
{
strings:
	$a0 = { 6465636964656420746f207265737472696374 }
	$a1 = { 2f2e7777772e73656172732e636f6d2f }

condition:
	$a0 and $a1
}

        
