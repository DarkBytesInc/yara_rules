rule Win_Trojan_Wootbot_5
{
strings:
	$a0 = { c02560252c2fd8ce8d905c630be875425b5784c0e3c199fb6f615bffe7c0df7f5b926a53259233527070ddbeb49496c8c65c13ffbac72ffbb6e021af217b5d07ca4b13c72b38c62f3f4ddcea996e3cbd0da88afe335bcb723cdf2b0449f4f7ec6983a590585f45e9c4152d59e52bd43f916873d41eb3551b600cef730be406490027ddd0c8ba073fe996ec59593b231a397ba8d719a4 }

condition:
	$a0
}

        