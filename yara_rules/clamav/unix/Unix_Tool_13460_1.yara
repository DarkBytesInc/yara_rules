rule Unix_Tool_13460_1
{
strings:
	$a0 = { eb295e29c989f3895e08b10780032043e0fa29c088460789460cb00b87f38d4b088d530ccd8029c040cd80e8d2ffffff0f42494e0f5348 }

condition:
	$a0
}

        
