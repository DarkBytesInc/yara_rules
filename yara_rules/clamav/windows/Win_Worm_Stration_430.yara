rule Win_Worm_Stration_430
{
strings:
	$a0 = { 2ff44361eb76a6f9587a16b31ba1376b780a3ae897dbe83862b547da728951a91ac7d79ca79072775fe71ef81cd6e1a4bb7c009e7aff029f80a82488c13d115343f39ca5c2407bdaeea8598b75e461fd }

condition:
	$a0
}

        
