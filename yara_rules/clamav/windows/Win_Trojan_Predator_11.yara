rule Win_Trojan_Predator_11
{
strings:
	$a0 = { 12b8be6ab9b104497808310d31054f4febf5b85952d2413a7079873a461ee2e679e16e2239b21569b547c36bc1213096a118e8c9ac6aafa90e78aae46b5957e476e9 }

condition:
	$a0
}

        
