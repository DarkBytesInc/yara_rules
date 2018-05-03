rule Html_Phishing_Auction_271
{
strings:
	$a0 = { 2e307837372f6d656e752f65626179697361 }

condition:
	$a0
}

        
