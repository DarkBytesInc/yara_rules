rule Win_Trojan_Delf_1552
{
strings:
	$a0 = { 8b45fc8b80fc0200008b55ece814058cb08b45fc8b80fc020000b201e814058c60ba5caa45008b45f8e8140577dc33c05a5959648910 }

condition:
	$a0
}

        
