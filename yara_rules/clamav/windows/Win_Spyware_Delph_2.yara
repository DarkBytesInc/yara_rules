rule Win_Spyware_Delph_2
{
strings:
	$a0 = { ffffffff200000005057535445414c2e42414e504145532e442056455253414f20322e302e302e3000000000ffffffff }

condition:
	$a0
}

        
