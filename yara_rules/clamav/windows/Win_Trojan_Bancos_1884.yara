rule Win_Trojan_Bancos_1884
{
strings:
	$a0 = { 23b1d66be68f10c0f4e7a4355ac28f11dbfb3baa0e261c5c60051f5fd847c8215692942524acb199895d770958075b8f058f005a229f2ac0ab30a43450dc83cb9d43915a95be }

condition:
	$a0
}

        
