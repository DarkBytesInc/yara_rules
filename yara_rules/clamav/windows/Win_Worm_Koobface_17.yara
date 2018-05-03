rule Win_Worm_Koobface_17
{
strings:
	$a0 = { 633a5c77696e646f77735c626f6c6976617232312e657865[0-16]474554 }
	$a1 = { 460061006300650062006f006f006b }

condition:
	$a0 and $a1
}

        
