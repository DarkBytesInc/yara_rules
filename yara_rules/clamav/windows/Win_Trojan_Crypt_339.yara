rule Win_Trojan_Crypt_339
{
strings:
	$a0 = { 833d04c24200ff31c074348735a6c0420083faff7e18013d81c042008d3595c04200c706760000008b0d24c042 }

condition:
	$a0
}

        
