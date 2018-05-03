rule Win_Worm_Nyxem_2
{
strings:
	$a0 = { 73e5bfb93dc7120e0d0c07004e657757696665bf7cffff010b00426c61636b576f726d2e4300039f194200220023c267 }

condition:
	$a0
}

        
