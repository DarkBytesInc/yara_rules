rule Win_Trojan__0536_0002_001_1
{
strings:
	$a0 = { 8f008b1eab06e86400b440b9a906bab606cd2126c74515000026c745170000b440b91a00ba600d }

condition:
	$a0
}

        
