rule Win_Worm_Bagle_182
{
strings:
	$a0 = { ffb680c00100ff7508ff152c9b010085c05959740d83c60481fe7405000072e0eb02b301 }

condition:
	$a0
}

        
