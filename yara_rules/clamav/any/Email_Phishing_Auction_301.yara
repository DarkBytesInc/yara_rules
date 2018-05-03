rule Email_Phishing_Auction_301
{
strings:
	$a0 = { 2f7777772e656261792e636f6d2f6542617949534150492e646c6c536967 }

condition:
	$a0
}

        
