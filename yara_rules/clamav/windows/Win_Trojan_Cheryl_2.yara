rule Win_Trojan_Cheryl_2
{
strings:
	$a0 = { 5b43686572796c2e425d005b4a65726b314e2f444946465553494f4e5d002a2e5458540022ad6da4b6716701 }

condition:
	$a0
}

        
