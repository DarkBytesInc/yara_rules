rule Email_Phishing_Auction_320
{
strings:
	$a0 = { 654261792073656e742074686973206d6573736167652066726f6d }

condition:
	$a0
}

        
