rule Win_Trojan_Frenzy_2
{
strings:
	$a0 = { ff022500008034000005006d4f7074730013010000030b0053686f77204672656e7a790004ffff022600008034010005006d4f7074730013010100030c0041626f7574204672656e7a790004ffff021b00008034030005006d4f70747300130103000301002d0006ffff021d }

condition:
	$a0
}

        