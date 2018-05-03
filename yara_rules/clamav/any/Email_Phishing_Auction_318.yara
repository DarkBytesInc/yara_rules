rule Email_Phishing_Auction_318
{
strings:
	$a0 = { 2e652f6367692e656261792e636f6d2f77732f }

condition:
	$a0
}

        
