rule Html_Trojan_ClickerSmall_73
{
strings:
	$a0 = { 69632e636f6d2f74dbfffff6732f696e0967693f616e7230303100433a5c50726f67226ddbffffb720236c6573005c49 }

condition:
	$a0
}

        
