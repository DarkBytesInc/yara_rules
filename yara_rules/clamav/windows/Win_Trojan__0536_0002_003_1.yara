rule Win_Trojan__0536_0002_003_1
{
strings:
	$a0 = { 018b1eab06e81801b440b9a906bab606cd2126c74515000026c745170000b440b90300ba7a06 }

condition:
	$a0
}

        
