rule Win_Worm_Autorun_392
{
strings:
	$a0 = { 6f00700065006e003d00530065007400750070002e006500780065 }

condition:
	$a0
}

        
