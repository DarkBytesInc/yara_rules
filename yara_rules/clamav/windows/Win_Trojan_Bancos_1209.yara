rule Win_Trojan_Bancos_1209
{
strings:
	$a0 = { afc2dcd162eac6d448351f1d27e59fed9fc43e37f9385d59b3ec9b17833211e9d0ef4a4bfd744956287abd9ef6d988c919b28a9a410c7d94aa57b9ffb9462274e1d496dfb8c8affed3dfeac46975bd4756cbcb177db9b078dbeb67106797d6 }

condition:
	$a0
}

        
