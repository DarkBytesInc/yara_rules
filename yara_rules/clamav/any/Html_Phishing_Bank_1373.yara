rule Html_Phishing_Bank_1373
{
strings:
	$a0 = { 696e206f7468657220746f2061766f696420616e206572726f72 }

condition:
	$a0
}

        
