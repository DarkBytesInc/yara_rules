rule Win_Worm_Kelvir_74
{
strings:
	$a0 = { 5068e41b40008975ac895da4e8d4f0ffff }

condition:
	$a0
}

        
