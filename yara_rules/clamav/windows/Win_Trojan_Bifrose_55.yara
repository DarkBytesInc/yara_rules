rule Win_Trojan_Bifrose_55
{
strings:
	$a0 = { 19fbcf01338d9e5e6409e9e8ee68e5f6e95a0c0fa676e3ca6ae6a0ef67848e91867ffc07a13d38ca8ce9d22eff05395a476da42f9621a167eeea81d15974bcbd654ad3eccd8d0f11d00fc8c909b7c4cc313d6936a41ae8eeb18f39a79914f66ced124ae6b409a936340f80e8ac25442a }

condition:
	$a0
}

        
