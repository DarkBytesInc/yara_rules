rule Win_Trojan_Delf_2246
{
strings:
	$a0 = { 7368656c6c657865637574653d726561646d652e657865 }
	$a1 = { 5c72656d6f7669626c65732e6765647a6163 }

condition:
	$a0 and $a1
}

        
