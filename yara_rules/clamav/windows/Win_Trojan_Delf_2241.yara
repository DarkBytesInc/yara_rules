rule Win_Trojan_Delf_2241
{
strings:
	$a0 = { baf4924500b858934500e8093600008b45fce81105fbff84c0741a8d4df8baf4924500b858934500e8eb3500008b45f8e80305fbff }

condition:
	$a0
}

        
