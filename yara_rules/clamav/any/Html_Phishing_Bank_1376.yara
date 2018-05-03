rule Html_Phishing_Bank_1376
{
strings:
	$a0 = { 75706461746520796f7572206163636f756e74 }
	$a1 = { 666f722074686520696e636f6e76696e69656e6365 }

condition:
	$a0 and $a1
}

        
