rule Html_Phishing_Bank_1374
{
strings:
	$a0 = { 776520696d706c6f726520796f7520746f206c6f67696e }
	$a1 = { 62616e6b696e67 }

condition:
	$a0 and $a1
}

        
