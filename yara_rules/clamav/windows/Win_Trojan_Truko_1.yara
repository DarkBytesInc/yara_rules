rule Win_Trojan_Truko_1
{
strings:
	$a0 = { 68140843006aff6a00e83c31fdff8b15c84c43008902a11c4c4300c600008d55e833c0e8ce3dfdff8b45e88d55ece8db3efdff8d45ec508d45e48b15c04c43008b12e8531ffdff8b55e458e8ca1ffdff8b45ece8b221fdff8bd0b824084300e8aafcffff }

condition:
	$a0
}

        
