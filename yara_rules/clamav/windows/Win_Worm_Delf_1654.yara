rule Win_Worm_Delf_1654
{
strings:
	$a0 = { ba04294500e85821fbff75316a018d45d88b4dfcbaf0284500e84420fbff8b45d8e8f021fbff50e82a3ffbff }

condition:
	$a0
}

        
