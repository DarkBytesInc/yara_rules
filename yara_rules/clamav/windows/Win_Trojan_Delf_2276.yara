rule Win_Trojan_Delf_2276
{
strings:
	$a0 = { 433a5c57494e444f57535c7368656c6c5c6f75742e657865 }
	$a1 = { 433a5c57494e444f57535c7368656c6c5c7570642e657865 }

condition:
	$a0 and $a1
}

        
