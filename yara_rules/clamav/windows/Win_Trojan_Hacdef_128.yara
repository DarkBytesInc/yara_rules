rule Win_Trojan_Hacdef_128
{
strings:
	$a0 = { 1ba44ff7977c1756deba64bc221210011fb695989091f5fd1b35e86b915044283e022b30662a817f765519e481c39b55d038638cf2b43aabe0598bdb98e64cf7617db0a4d11f4414d2bb7b79961d389c282a6853cb7fc6c9642707d13973d24142bedab2e721bb0f9c0c98cfd47b44486f8e4f32aaa88adff5f0d5528e4d7187d6d63e0a }

condition:
	$a0
}

        