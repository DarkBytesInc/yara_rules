rule Win_Downloader_Banload_461
{
strings:
	$a0 = { 8faace8a2037acc6d87043edae9e71d6428a6696b9f4d8f38cd3a9ea0ac8de58bcc67089657e5049b98bdceb5c28529c073fd732323534868f968aa4d100379d4d3e3764bd31d4bd1799766156e4d2c19217b142 }

condition:
	$a0
}

        
