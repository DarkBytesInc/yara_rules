rule Html_Phishing_Auction_210
{
strings:
	$a0 = { 68656c6c6f2064656172206d656d6265722c203c62723e2d2d2d2d2d2d2d2d2d[0-100]2d2d2d2d2d2d2d2d2d203c62723e796f75722072656769737465726564206e616d6520697320696e636c7564656420746f2073686f772074686973206d657373616765206f726967696e617465642066726f6d206562 }

condition:
	$a0
}

        