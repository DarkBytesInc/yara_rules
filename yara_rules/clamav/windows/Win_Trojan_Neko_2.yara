rule Win_Trojan_Neko_2
{
strings:
	$a0 = { a8ecaafc9e2925902de905e9046c4d0504695d044a454941044d57046a414f4b0a2e296d50044d570445046e4554454a }

condition:
	$a0
}

        
