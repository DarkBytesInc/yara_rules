rule Win_Trojan_Fakeav_22
{
strings:
	$a0 = { 8b0d3800fe7f81c92000200081f969006e00757a }
	$a1 = { 696e7374616c6c6174696f6e206f6620416e7469766972757320506c7573 }

condition:
	$a0 and $a1
}

        
