rule Win_Trojan_Psycho_4
{
strings:
	$a0 = { 6174746163686d656e74732e6164642022633a5c77696e646f77735c70737963686f2e646f6322 }

condition:
	$a0
}

        
