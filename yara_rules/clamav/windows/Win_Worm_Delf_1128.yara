rule Win_Worm_Delf_1128
{
strings:
	$a0 = { 558bec83c4d08955d08945d4b8709a4600e816b805006a00683a934600e81c530600 }

condition:
	$a0
}

        
