rule Win_Trojan_VGEN_625
{
strings:
	$a0 = { 9a0000a3029a000041029afe02e9015589e5b800039a7c02a30281ec00038dbe00ff1657bf12030e579a01021a02bf17 }

condition:
	$a0
}

        
