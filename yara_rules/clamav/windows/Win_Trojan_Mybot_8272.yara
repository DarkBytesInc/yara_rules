rule Win_Trojan_Mybot_8272
{
strings:
	$a0 = { 6bef0002cb946f00889f27c191208dc5f88885ec8b6f0ab5558cc483cfa322081a4e06708a4f9b70d1b573735585641a912af4aad8490f28c000d4b8c49649ad89b2e4ba99f8 }

condition:
	$a0
}

        
