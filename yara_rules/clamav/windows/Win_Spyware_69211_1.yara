rule Win_Spyware_69211_1
{
strings:
	$a0 = { c605e051420000e8684d000050e800000000ff257c8342 }
	$a1 = { 5c656565772e657865657865 }
	$a2 = { 0307616e74692e6578 }
	$a3 = { 4e4545453a20446974206973 }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
