rule Win_Trojan_Bancos_974
{
strings:
	$a0 = { d100ec3f36238177da64caf97dc73b4a46550faa139d3e1496ba981c80f34ebc086d50fd0aa7baa71fb1eb38a8f45b7d632c65e0214c7e6b3602fb06006c4d33c1c12f5e428d55bda89ed02723ab33996b3ec67e23 }

condition:
	$a0
}

        
