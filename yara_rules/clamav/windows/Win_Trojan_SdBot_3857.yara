rule Win_Trojan_SdBot_3857
{
strings:
	$a0 = { 8b9c99e43157bc5e4fa02ea02ba46ec0e335210f79a510261b7bf8df2ebb4d38c3f04838d9366bdb16dcfe3ffb356c69b6fe6d427ffd13d8877a730993cc8a48f7e8b1821adb2854f57defaa22ee9ce128b7b8b6b4 }

condition:
	$a0
}

        
