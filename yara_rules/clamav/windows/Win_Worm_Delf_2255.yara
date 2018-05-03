rule Win_Worm_Delf_2255
{
strings:
	$a0 = { 7478742e65646f63 }
	$a1 = { 6578652e316565725c }
	$a2 = { 6578652e326565725c }

condition:
	$a0 and $a1 and $a2
}

        
