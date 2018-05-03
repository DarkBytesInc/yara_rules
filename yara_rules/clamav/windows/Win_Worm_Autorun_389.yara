rule Win_Worm_Autorun_389
{
strings:
	$a0 = { 558bec5356bba08c410043803b00743de8000000005e83c64ab91dee00002be1 }

condition:
	$a0
}

        
