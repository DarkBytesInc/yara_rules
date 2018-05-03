rule Win_Worm_Koobface_19
{
strings:
	$a0 = { 633a5c77696e646f77735c666d61726b322e646174[0-29]5c626f6c6976617232332e657865[0-16]474554 }

condition:
	$a0
}

        
