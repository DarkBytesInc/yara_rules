rule Win_Worm_Info_2
{
strings:
	$a0 = { 01b409cd21b4c0cd15268a4702bae2013cff7426baeb013cfe741fba02023cfd7418baee013cfc7411baf1013cf9 }

condition:
	$a0
}

        
