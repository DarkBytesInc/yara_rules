rule Win_Trojan_Burger_25
{
strings:
	$a0 = { b800002ea371032ea3f9022ea2fb02b419cd2104412ea2fc02b447b6002e8a16fc028d362903cd21b40e2e8a16fc02cd212ea2fb02b0013c017502b006b4008d }

condition:
	$a0
}

        
