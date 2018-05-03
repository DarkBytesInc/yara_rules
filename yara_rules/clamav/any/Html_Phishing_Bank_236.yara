rule Html_Phishing_Bank_236
{
strings:
	$a0 = { 2f7e6b6576696e2f726f79616c2f223e68747470733a2f2f777777312e726f79616c62616e6b2e636f6d2f6367692d }

condition:
	$a0
}

        
