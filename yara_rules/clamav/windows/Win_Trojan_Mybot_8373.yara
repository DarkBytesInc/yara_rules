rule Win_Trojan_Mybot_8373
{
strings:
	$a0 = { cab4f4a3e15e2dc312adebe0867e68c1be27803da83c91a676b83a72b1665623c19ab4caa823be2a2b2d5fa10a2dfeabd74377d4b1a79828414254371eb98ac621253f62017df74eea48bb2c11f42655e8ec790a38 }

condition:
	$a0
}

        
