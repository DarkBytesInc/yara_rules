rule Email_Phishing_Auction_297
{
strings:
	$a0 = { 654261792073656e742074686973206d65737361676520746f20796f75 }

condition:
	$a0
}

        
