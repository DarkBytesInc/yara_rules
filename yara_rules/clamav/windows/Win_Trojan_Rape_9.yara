rule Win_Trojan_Rape_9
{
strings:
	$a0 = { 5e81ee03008beefc5006561eb42acd213c007502eb03e9c901b401b92020cd10b40233d2cd1033c0cd10b40eb049cd10b40eb074cd10b40eb027cd10b40eb073cd10b40eb020cd10b40eb053cd10b40eb075cd10b40eb06ecd10b40eb0 }

condition:
	$a0
}

        
