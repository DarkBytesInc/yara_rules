rule Win_Trojan_Agent_35853
{
strings:
	$a0 = { 646c6c000000002e657865 }
	$a1 = { 312d5f746561717074762c63766300312d5f74657071762c63766300312d5f74 }

condition:
	$a0 and $a1
}

        
