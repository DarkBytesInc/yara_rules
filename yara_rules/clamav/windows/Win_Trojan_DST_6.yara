rule Win_Trojan_DST_6
{
strings:
	$a0 = { 90061e5051525657e800005bb800008ed8a116053d4f43745e1e07b84f4326a316050e1f8cd8488ed8a103002d46 }

condition:
	$a0
}

        
