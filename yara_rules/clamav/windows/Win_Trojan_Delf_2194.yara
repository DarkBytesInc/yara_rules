rule Win_Trojan_Delf_2194
{
strings:
	$a0 = { 4d70627549732b2f548f3eec6d7f6d202f6e6174572fb6f0622f77e26f0b4b37acfdb6633973777368b1b237764bd6be275313271c45789f18bc }

condition:
	$a0
}

        
