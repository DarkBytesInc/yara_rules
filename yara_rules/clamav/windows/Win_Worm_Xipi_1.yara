rule Win_Worm_Xipi_1
{
strings:
	$a0 = { 65725c00005e8dbdfcfeffffa4807eff0075f98d85fcfeffff50e812000000ac0ac075fb8dbdfcfeffff803e0075ddc9c3558bec81c4f8feffff56e82d2000005061756c69 }

condition:
	$a0
}

        
