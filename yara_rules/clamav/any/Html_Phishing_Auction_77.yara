rule Html_Phishing_Auction_77
{
strings:
	$a0 = { 64656172206562617920757365722c3c62723e3c62723e64756520746f20726563656e742061637469766974792c20696e636c7564696e6720706f737369626c6520756e617574686f7269736564206c697374696e677320706c61636564206f6e20796f7572206163636f756e74 }

condition:
	$a0
}

        