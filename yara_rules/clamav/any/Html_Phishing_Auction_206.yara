rule Html_Phishing_Auction_206
{
strings:
	$a0 = { 363636362073697a653d313e3c623e6562617920696e7465726e6174696f6e616c2061672073656e742074686973206d65737361676520746f20796f752e3c2f623e3c62723e796f75722072656769737465726564206e616d6520697320696e636c75646564 }

condition:
	$a0
}

        