rule Win_Trojan_Lineage_500
{
strings:
	$a0 = { d51c48d34cedaa293bbca8da255749408ec697b86483e4af9b106b51769055c7f5455b568c96353ac78a5154bbd4ec90803089caf9be2252ac29e19e1fd86e4e79dbd6dd6e3beae7c11f55d2bb8a8d00efac4b9b7b859433af3f3b93e909d3b801bf }

condition:
	$a0
}

        
