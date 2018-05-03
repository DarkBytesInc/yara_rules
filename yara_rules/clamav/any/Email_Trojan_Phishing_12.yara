rule Email_Trojan_Phishing_12
{
strings:
	$a0 = { 6c69636b2068657265[1-50]746f2075706461746520796f757220636f6e7461637420656d61696c }

condition:
	$a0
}

        
