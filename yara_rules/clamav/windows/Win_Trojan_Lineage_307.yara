rule Win_Trojan_Lineage_307
{
strings:
	$a0 = { cb69fbf3d9c9651641cb035795708f45e0ef315a63483f5b75d96cdd440a7a5db21f4f4914e5b8dbb91040f4eb5d849d040e7c9dbea43870041988cde5403491270cbac88de85ffefca689c3f02d385f173aebbcd584e53e0b9d3f2b }

condition:
	$a0
}

        
