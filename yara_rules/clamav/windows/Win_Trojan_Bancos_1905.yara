rule Win_Trojan_Bancos_1905
{
strings:
	$a0 = { 4f6bb4adfb4961c39c34d04f5a3432078e82096f0e6aa1fc32e6538eed3f411d30017c171fc2a56cb9176ccc77a98c5eac204f57f44b90cb13631c048f933d59044f4c4e29a0 }

condition:
	$a0
}

        
