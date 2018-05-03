rule Win_Worm_Dasher_11
{
strings:
	$a0 = { 5753576818254000ffb58cfbffffe8390300006804254000ffb58cfbffffe829030000 }

condition:
	$a0
}

        
