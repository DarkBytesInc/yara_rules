rule Win_Trojan_Delf_2274
{
strings:
	$a0 = { 8b95f8fcffff8d45f4b95cd64500e8b87afaff8d45e0ba7cd64500e83778faff8d45dcbab8d64500e82a78faff8d85f4fcffffb9f4d645008b55f4e88b7afaff8b85f4fcffffe85cc4faff84c00f84d50300008d85f0fcffff8bd3e81364fbff8b95f0fcffffb80cd74500e8537dfaff85c00f85b0030000 }

condition:
	$a0
}

        
