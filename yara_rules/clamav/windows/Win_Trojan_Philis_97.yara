rule Win_Trojan_Philis_97
{
strings:
	$a0 = { 57bf00301a2c81c7970606ef03f75f54689736201b2b342483c404893424565283c404890c2481c66a4f40795481 }

condition:
	$a0
}

        