rule Win_Trojan_DST_2
{
strings:
	$a0 = { 0190061e5051525657e800005bb800008ed8a116053d4f43744d1e07b84f4326a316050e1f2ea102002d0008508ec0 }

condition:
	$a0
}

        
