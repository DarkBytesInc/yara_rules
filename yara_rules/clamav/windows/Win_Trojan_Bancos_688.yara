rule Win_Trojan_Bancos_688
{
strings:
	$a0 = { 10e09c67246f01284204392947bc466f0ff2d82ea3e300012f5dbe1b10ea7d09163d8ad0e2427e8d445f6bd52197a1ad811b09f2663942675e827b5e39f8e6e2 }

condition:
	$a0
}

        
