rule Win_Worm_Delf_1505
{
strings:
	$a0 = { 74136a1068b446151368c44615136a00e8911cffff }

condition:
	$a0
}

        
