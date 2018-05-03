rule Html_Phishing_Pay_272
{
strings:
	$a0 = { 6e2e706372656e742e636f6d2e6d782f73736c2f7765627363722f696e64 }

condition:
	$a0
}

        
