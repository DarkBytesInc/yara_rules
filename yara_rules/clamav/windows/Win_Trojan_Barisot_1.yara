rule Win_Trojan_Barisot_1
{
strings:
	$a0 = { bae08940008bc3e878baffffba010000008bc3e816bdffffe80d9dffff85c075456a00ba84c84000b9253a00008bc3e8f2baffff8bc3e84fbbffffb858184100baf8894000e894a8ffffb8d41741008b1558184100e8a4d5ffff6a0068d4174100e8e8c6ffff }

condition:
	$a0
}

        
