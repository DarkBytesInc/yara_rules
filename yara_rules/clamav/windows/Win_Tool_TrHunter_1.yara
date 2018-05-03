rule Win_Tool_TrHunter_1
{
strings:
	$a0 = { 536f66747761725e65dfcc3f4cbf6379f6739ed84b2390b8084b11241b82e9102b7c7645a312 }

condition:
	$a0
}

        
