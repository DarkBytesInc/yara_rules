rule Win_Worm_Nohoper_2
{
strings:
	$a0 = { e804000000[0-4]812c24052040005b8bebbb8404000081eb8404000003dd83fb00741b8dbd40204000ba2a070000 }

condition:
	$a0
}

        
