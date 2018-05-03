rule Email_Phishing_Yaleedu_1
{
strings:
	$a0 = { 64656c6574696e6720616c6c206f7572202859616c65202e45647529 }
	$a1 = { 77697468696e20536576656e2064617973 }

condition:
	$a0 and $a1
}

        
