rule Html_Trojan_Ascii46_161_0_201_1
{
strings:
	$a0 = { 34362e3136312e302e323031 }

condition:
	$a0
}

        
