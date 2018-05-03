rule Win_Worm_Delf_141
{
strings:
	$a0 = { 616b697261782e65786520776f726d1b23417ca3ffbf41424344 }

condition:
	$a0
}

        
