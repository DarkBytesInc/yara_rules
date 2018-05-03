rule Win_Worm_Autorun_451
{
strings:
	$a0 = { 43003a002f00570031[0-27]2e006500780065 }
	$a1 = { 43003a005c0073[0-21]6400720069007600650072002e }
	$a2 = { 6f006e005c00520075006e }

condition:
	$a0 and $a1 and $a2
}

        
