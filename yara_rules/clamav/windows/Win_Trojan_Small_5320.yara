rule Win_Trojan_Small_5320
{
strings:
	$a0 = { 64c69caeb4a4df1b60a52b7365e55d0cb8096ed014ba19e8f81283e9f7187745fb7c6e738c0b6a3bf610a465a83c7ef09f446024a380289fe8bf9eb129071567df46c9f0a0b91973e6b5a4f6d28b }

condition:
	$a0
}

        
