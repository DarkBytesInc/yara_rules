rule Win_Trojan_VGEN_10
{
strings:
	$a0 = { 3c16558bec83ec02b8000050a1820405010050e81b1483c404a1f604b95000f7e90306f80499e86722be8e04e81222 }

condition:
	$a0
}

        
