rule Win_Trojan_Lineage_505
{
strings:
	$a0 = { be2252ac29e19e1fd86e4e79dbd6dd6e3beae7c11f55d2bb8a8d00efac4b9b7b859433af3f3b93e909d3b801bfb1c81176c015f7c1b805b990a90f4f98b4bca5f50469855582a221efd2fbf7e64fb54a14e40fc427c5761c2bf593d7d1408d324a66 }

condition:
	$a0
}

        
