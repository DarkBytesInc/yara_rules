rule Win_Trojan_Lineage_499
{
strings:
	$a0 = { bc0fb02bc6ece1baeafc866e41c4746c08d9d51c48d34cedaa293bbca8da255749408ec697b86483e4af9b106b51769055c7f5455b568c96353ac78a5154bbd4ec90803089caf9be2252ac29e19e1fd86e4e79dbd6dd6e3beae7c11f55d2bb8a8d00 }

condition:
	$a0
}

        
