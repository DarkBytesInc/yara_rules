rule Win_Trojan_Bancos_1770
{
strings:
	$a0 = { f2af3cf35183932d61a22f431b96ecd4b19bb57362ec538318d8553e019d008001cd6d38185946df4453c9fab12a9a0ff7cf9002eb58db99d5b6ce7950d6a5da9804984284c5 }

condition:
	$a0
}

        
