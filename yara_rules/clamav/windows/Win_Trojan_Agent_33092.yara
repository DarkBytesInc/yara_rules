rule Win_Trojan_Agent_33092
{
strings:
	$a0 = { f5d5ba89435446e6d0bfa91c5454f92565bb000e023ac15c367a05d338756539e38a317e3466fd6e3297e90d41437200a21fbf777c4246a9aa2812c7f7e9220de36965a1eca3aff0917689e3e9cd66534ac87ea0ae8f4bfe7480c1cc4c715d6793b6 }

condition:
	$a0
}

        