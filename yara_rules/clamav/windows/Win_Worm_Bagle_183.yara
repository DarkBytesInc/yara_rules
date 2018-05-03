rule Win_Worm_Bagle_183
{
strings:
	$a0 = { 6840484048688d5b0090eb01ebeb0a5ba9ed46 }

condition:
	$a0
}

        
