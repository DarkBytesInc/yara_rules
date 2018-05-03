rule Win_Worm_Delf_1530
{
strings:
	$a0 = { 33c05a5959648910685d8f40008d45f8ba02000000e800002e6cc3 }

condition:
	$a0
}

        
