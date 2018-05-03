rule Win_Tool_Forkbomb_1
{
strings:
	$a0 = { 31c999b802000000cd80ebf7 }

condition:
	$a0
}

        
