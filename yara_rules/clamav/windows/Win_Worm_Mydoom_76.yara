rule Win_Worm_Mydoom_76
{
strings:
	$a0 = { 457273726572653a2075676763663a2f2f6a6a6a2e }
	$a1 = { 536553687574646f776e50726976696c65676500 }

condition:
	$a0 and $a1
}

        
