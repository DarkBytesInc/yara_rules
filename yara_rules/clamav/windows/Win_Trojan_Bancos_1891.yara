rule Win_Trojan_Bancos_1891
{
strings:
	$a0 = { 25eb3af4a91f2179a605b770a281617029d7d8700acffbd48d2165b4f5714904d0678da55b6cf104dbfc217a0645ca88f8d307d5990797be706e4ceccec42e4813e83f0ba04d }

condition:
	$a0
}

        
