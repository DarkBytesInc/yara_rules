rule Win_Trojan_Bancos_1004
{
strings:
	$a0 = { 1cca64f0080886db06906d3dca73eb98ff52aa22a748c1b3b892390d2ed6657b4fa5f993305a12b1701c05e8cc28e1075f3ad0e5924fd3faec5fbf74f8a12e5539a1bb3f8ee53b057b2e67821f58c0cf9e5990ab44 }

condition:
	$a0
}

        
