rule Email_Phishing_Acc_39
{
strings:
	$a0 = { 46726f6d3a }
	$a1 = { 3c696e666f40636f6e74696e75652e636f6d3e }
	$a2 = { 576520617265206c6f6f6b696e6720666f7220736563726574206576616c7561746f7273 }

condition:
	$a0 and $a1 and $a2
}

        
