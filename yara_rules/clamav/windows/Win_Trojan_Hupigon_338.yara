rule Win_Trojan_Hupigon_338
{
strings:
	$a0 = { f3fecf8eea9636a6a823ed0107c30f12b42ba290b3726b57c97f0681a6f10c61b4d2df1bcc30f5be323fdd2f03ca8e0e55de0cd45b188399320de58a85324146b74b4a5b5f77c076730ba166c96cd8cba38e987178b6bd1142ba }

condition:
	$a0
}

        
