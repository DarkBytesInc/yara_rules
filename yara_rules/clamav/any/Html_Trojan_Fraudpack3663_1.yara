rule Html_Trojan_Fraudpack3663_1
{
strings:
	$a0 = { 31d101d1198da0feffff0b9520ffffff898de8feffffff8590feffffff85e0feffffbad90000003155d40995b0feffff4281fa2b09000075231b4db042114dac31c983c14281e9000d0000234dc801ca899560feffffff85fcfeffff8b8dd4feffff09c1 }

condition:
	$a0
}

        
