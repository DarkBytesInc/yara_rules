rule Win_Trojan_Lineage_344
{
strings:
	$a0 = { 6e5aba15c328c01e68bf3d4b38d7d7f937d73fccf8d8ba3539d73ff73cd63f490b2869c4bd3bc3b6c7806fa16d2ec0b6bb1333c4bd3bc3b6c7816fa1b1d83f49b552d3b5c7286fa10dd83f49031030cdeed73f49b397331a6f5c3f468e9f3d468e8f3ec0 }

condition:
	$a0
}

        
