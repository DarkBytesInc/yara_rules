rule Win_Trojan_Crypted_10
{
strings:
	$a0 = { e801000000e8585b81e300ffffff66813b4d5a753784db75338bf303733c813e5045000075260fb746188bc869c0ad0b0000f7e02dab5d414b69c9dec00000 }

condition:
	$a0
}

        
