rule Win_Trojan_VGEN_624
{
strings:
	$a0 = { 9a000057005589e5b802029a7c02570081ec02029aa1075700bf00000e57bf8a071e57b8ff00509a2d055700c6068a08 }

condition:
	$a0
}

        
