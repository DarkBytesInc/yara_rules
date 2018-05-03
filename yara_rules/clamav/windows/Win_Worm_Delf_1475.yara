rule Win_Worm_Delf_1475
{
strings:
	$a0 = { 57d3cf5f60505690b8e31eba0681ee }

condition:
	$a0
}

        
