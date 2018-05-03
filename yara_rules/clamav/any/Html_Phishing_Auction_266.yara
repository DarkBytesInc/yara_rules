rule Html_Phishing_Auction_266
{
strings:
	$a0 = { 2e3139322e39372f654261794953415049646c6c5369676e496e6661766f726974 }

condition:
	$a0
}

        
