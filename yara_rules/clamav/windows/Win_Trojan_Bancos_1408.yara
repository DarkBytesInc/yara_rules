rule Win_Trojan_Bancos_1408
{
strings:
	$a0 = { b490fe5e6a855c62a0a35c65a167eaded2ae91d9ff1f7fa9f3fabf19f2e2ba888b42011dfa3e32253e58da41faae02434a3cb1dc7a0d7def2fc2c352630c2526e63da2c5eccc3d9792fdb3ead077cc876bcdb3f2e1acfb9f4f963370 }

condition:
	$a0
}

        
