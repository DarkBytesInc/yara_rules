rule Html_Phishing_Auction_270
{
strings:
	$a0 = { 2f313338373934393632322f686f7264652f7365 }

condition:
	$a0
}

        
