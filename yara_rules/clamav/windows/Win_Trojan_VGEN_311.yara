rule Win_Trojan_VGEN_311
{
strings:
	$a0 = { 5351521e069c0633c08ed8a184003df0017403eb0490eb4890a184002ea31901a186002ea31b0107068cc0488ed8bb }

condition:
	$a0
}

        
