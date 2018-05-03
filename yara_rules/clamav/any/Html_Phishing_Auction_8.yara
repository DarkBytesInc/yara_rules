rule Html_Phishing_Auction_8
{
strings:
	$a0 = { 3c6120687265663d22687474703a2f2f7777772e70617970616c2e636f6d25303040 }

condition:
	$a0
}

        
