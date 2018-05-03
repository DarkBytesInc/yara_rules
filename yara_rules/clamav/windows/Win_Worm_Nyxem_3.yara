rule Win_Worm_Nyxem_3
{
strings:
	$a0 = { 73c7127ff96f6e0e0d0c07004e657757696665010b00426c61bd2ddfff636b576f726d2e4300039f1942900023be4239 }

condition:
	$a0
}

        
