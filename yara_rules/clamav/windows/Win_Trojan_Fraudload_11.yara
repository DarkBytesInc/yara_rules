rule Win_Trojan_Fraudload_11
{
strings:
	$a0 = { 64e127ea2ab1f9f384b6057087e137e0b0d15d0a96e1d4f9b1dc75b783e1c105bd3aeff8b3eae701826333fc89ff9403e7e1d7a18397b4f8b33567fdffff5d27e0f69520e86be0eb83ffffe0b2221a7231b134fc93cfaad712fa83775ffac7ecc1faff8a }

condition:
	$a0
}

        
