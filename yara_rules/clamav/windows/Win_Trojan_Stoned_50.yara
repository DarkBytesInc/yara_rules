rule Win_Trojan_Stoned_50
{
strings:
	$a0 = { c00780fc02751e81fa8000750f83f9017513b107e80c00b101ca02000ad27505e807009c0eea00000000061e57 }

condition:
	$a0
}

        
