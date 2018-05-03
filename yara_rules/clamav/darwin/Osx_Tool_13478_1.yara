rule Osx_Tool_13478_1
{
strings:
	$a0 = { 7c631a7939400106380aff1e44ffff026060606039400119380aff1e44ffff02 }

condition:
	$a0
}

        
