rule Html_Phishing_Bank_1473
{
strings:
	$a0 = { 7520616c6f72732071756520766f757320617669657a2064726f697420 }
	$a1 = { 3c6120687265663d22 }
	$a2 = { 636c697175657a20696369 }

condition:
	$a0 and $a1 and $a2
}

        
