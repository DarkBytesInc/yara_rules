rule Win_Spyware_143_2
{
strings:
	$a0 = { ca11c8df34276b10a5023d2bd1ff6685088c44e4f76d3baa3caca087b321c765cc705bdf31d40eef670d871f5a1a11810fe3ed0b6c40c9e30b8be8f831c6ab87dca902413e95fce7c1eddeb3493f7c0da8d4a97e5f852d634ad32a35fbd0 }

condition:
	$a0
}

        
