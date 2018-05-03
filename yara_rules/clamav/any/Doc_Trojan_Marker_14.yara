rule Doc_Trojan_Marker_14
{
strings:
	$a0 = { 436f6e7374206b6572203d20224d69f172ee73ee667420ce66666963e522 }

condition:
	$a0
}

        
