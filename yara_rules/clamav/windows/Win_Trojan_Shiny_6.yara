rule Win_Trojan_Shiny_6
{
strings:
	$a0 = { 5d1e0633ff8edf813e0400550174318cc048812e130401008ed8812e03004000812e120040008e0612000e1f8d }

condition:
	$a0
}

        
