rule Email_Phishing_Auction_265
{
strings:
	$a0 = { 696e67696e65696261792e636f6d2f6c6f67696e2e68746d6c3f }

condition:
	$a0
}

        
