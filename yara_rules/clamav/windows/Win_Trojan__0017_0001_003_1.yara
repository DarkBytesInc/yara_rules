rule Win_Trojan__0017_0001_003_1
{
strings:
	$a0 = { ee50f7d8250f008bc85803c150b440cd21582d0300c604e98944018bd6b985092bd1050301 }

condition:
	$a0
}

        
