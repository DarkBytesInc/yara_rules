rule Win_Trojan_MadWill_1
{
strings:
	$a0 = { b430cd213c03720580fc317544b4098d961c01cd21b44ccd21546869732070726f6772616d2072657175697265 }

condition:
	$a0
}

        
