rule Win_Trojan_Bancos_1313
{
strings:
	$a0 = { f7132994b124eff5e0b9a85fa115fbc1cefd2fe1ed152b5d7ff80d7864155a5d2b62e4f5e1a0951f5f8d640b5ab2d4eb84c58a54371a25cc6e4e97e42cb9be99aa2ec361fb7f6a91b325295d9dfd804f2d3372280268318105d2 }

condition:
	$a0
}

        
