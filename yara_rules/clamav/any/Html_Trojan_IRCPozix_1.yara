rule Html_Trojan_IRCPozix_1
{
strings:
	$a0 = { 5b66696c657365727665725d207761726e696e673d6f6666205b6463637365727665725d206e303d302c35392c302c302c302c30205b6167656e745d20656e61626c653d302c302c3020636861723d6d65726c696e2e616373 }

condition:
	$a0
}

        