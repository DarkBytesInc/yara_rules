rule Win_Trojan_VGEN_6
{
strings:
	$a0 = { 5e81ee03018cddb8dcfecd2172578cd8488ed8803e00005a740603060300ebf1813e03004100723d812e030040000306 }

condition:
	$a0
}

        
