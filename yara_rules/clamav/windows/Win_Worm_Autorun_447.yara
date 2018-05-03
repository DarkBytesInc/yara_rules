rule Win_Worm_Autorun_447
{
strings:
	$a0 = { 5b006100750074006f00720075006e005d }
	$a1 = { 6f00700065006e003d }
	$a2 = { 6100750074006f00720075006e002e006500780065 }

condition:
	$a0 and $a1 and $a2
}

        
