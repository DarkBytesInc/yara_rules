rule Win_Trojan_R_104
{
strings:
	$a0 = { FA3?DB8ED3368926FE7BBCFE7B1E6660????????1304[0-8]C1E0068EC0[0-4]BE007C3?FFB90001F3A5 }

condition:
	$a0
}

        
