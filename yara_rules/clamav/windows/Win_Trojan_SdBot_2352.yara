rule Win_Trojan_SdBot_2352
{
strings:
	$a0 = { f8fc8d994f07c839d8da848f0d4acede7357efe9021b318e4b92eb5b35cbd05d60d66c526f044f5360d9871e8866ec78b48b029b78a7988cdf69ad2ab1931b33c1f74e8cf62e71fa37bae399b7b4d2de18963cde27 }

condition:
	$a0
}

        
