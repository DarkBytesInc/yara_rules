rule Win_Trojan_DNSChanger_136
{
strings:
	$a0 = { 30adde6f30ade52a4a6238e35aeeaf886ae3e81a772e6e3e911a4a7e869b92919137eaae371b47911a4a62867a919191eaae371a75e3e8ca752e6e3e911a4a7e86fc91919137eaae371a6b046f3630adeda69130ad3be5823fed0b926e38e51b66eb981a }

condition:
	$a0
}

        
