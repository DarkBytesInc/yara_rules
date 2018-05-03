rule Win_Worm_Nihilit_7
{
strings:
	$a0 = { e925e4ffff0000002008bd711e6c030000000000000000003e6c03002e6c0300266c03 }

condition:
	$a0
}

        
