rule Win_Trojan_Bancos_1397
{
strings:
	$a0 = { ccc6e7329cfb766a3ad90da993904ea83c0f1f41c6f1795bf6add0769e2f2be566dbd9a6e7fdbd6b09c498a99d0608ecaae138da0e32db87030459d8bdd552cd510fa500f0a94a94652d22a802f54765eda35e5d6cf60173d83c1ebeaa257f87af59bd5848c37c00 }

condition:
	$a0
}

        
