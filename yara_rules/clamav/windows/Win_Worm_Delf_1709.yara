rule Win_Worm_Delf_1709
{
strings:
	$a0 = { ba90594000e83addffff8d430cbab0594000e82dddffff8bc3e8f2f9ffff8bc3e8e3d3ffff }

condition:
	$a0
}

        
