rule Win_Dropper_INService_3
{
strings:
	$a0 = { 2fdddb816898a966ea75096a39f0dbffdbb7ebc58b4008665ce666c745e402008b460c8b0400dd7c6f6f0fe86a105ee450537ef6750b5395aefdf399fcecff35b4d04bddfa81bd39b30bb09802106850faecffbfb91cef188d70018a084084c9 }

condition:
	$a0
}

        
