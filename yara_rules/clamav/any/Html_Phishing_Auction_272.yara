rule Html_Phishing_Auction_272
{
strings:
	$a0 = { 772e6167656f642e636f6d2f6973617069646c6c7369676e696e26707573657269643d26 }

condition:
	$a0
}

        
