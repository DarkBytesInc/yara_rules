rule Html_Phishing_Auction_208
{
strings:
	$a0 = { 6f6c6f723d22363636363636223e3c623e656261792073656e742074686973206d6573736167653c62723e3c2f623e74686973206d657373616765206f726967696e61 }

condition:
	$a0
}

        