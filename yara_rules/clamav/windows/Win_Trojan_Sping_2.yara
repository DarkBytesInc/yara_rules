rule Win_Trojan_Sping_2
{
strings:
	$a0 = { 8b45f48945e48d45f0506a008b450c83c0088b1052e87efcffff83c40c89c083f8ff7508b8ffffffffeb7d908b450c8b105268a88c0408e834faffff }
	$a1 = { 5350494e4720312e300a006279204461746167 }

condition:
	$a0 and $a1
}

        
