rule Win_Trojan_Agent_32841
{
strings:
	$a0 = { 47ac661f46b43bb303de31b1e36583a736a1512b9088124b637409a19f7481ccf3445fbc0700b1106bf9c84dae020fe07f3c5d97a0a3a4262f54457c9ac5bd12d3 }

condition:
	$a0
}

        
