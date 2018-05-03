rule Email_Phishing_DblDom_132
{
strings:
	$a0 = { 6f6e6c696e65206163636f756e74 }
	$a1 = { 2f757067726164652e68616c696661782d6f6e6c696e652e636f2e756b2f }

condition:
	$a0 and $a1
}

        
