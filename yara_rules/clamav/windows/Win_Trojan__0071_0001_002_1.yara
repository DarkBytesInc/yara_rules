rule Win_Trojan__0071_0001_002_1
{
strings:
	$a0 = { 8db60601e8690051b90300b4408d96c004cd21b440598d965c05cd2132c0e82e008d96bc04cd21 }

condition:
	$a0
}

        
