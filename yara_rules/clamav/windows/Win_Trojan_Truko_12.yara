rule Win_Trojan_Truko_12
{
strings:
	$a0 = { 68640743006aff6a00e8f431fdff8b15c84c43008902a11c4c4300c600008d55e833c0e8863efdff8b45e88d55ece8933ffdff8d45ec508d45e48b15c04c43008b12e80320fdff8b55e458e87a20fdff8b45ece86222fdff8bd0b874074300e8aafcffff }

condition:
	$a0
}

        
