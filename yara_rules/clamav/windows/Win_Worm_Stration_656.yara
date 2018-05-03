rule Win_Worm_Stration_656
{
strings:
	$a0 = { a5a5a5a4a4c745fc00000000837dfc11 }
	$a1 = { eb11bb01000000eb0a85d27505bb010000004185db74ca8a1180fa207f1084d2740c418a1980fb207f0484db75f45b8bc1c3cccccccccccc }
	$a2 = { 200000002e657865000000005c000000 }

condition:
	$a0 and $a1 and $a2
}

        
