rule Win_Trojan_AirRaid_5
{
strings:
	$a0 = { 6720312e305d50531ee83d0289470a894f0c8917897704897f02c64728ccf6470c01740ae85002b0ffd2e88847 }

condition:
	$a0
}

        
