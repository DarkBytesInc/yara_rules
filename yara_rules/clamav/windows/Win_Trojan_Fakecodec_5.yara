rule Win_Trojan_Fakecodec_5
{
strings:
	$a0 = { ff2b85bcfdffff1985b0feffff09d04831d039850cfeffff77448b955cffffff89950cffffff299588fdffff09c233950cffffff2395fcfdffff21c24a395598761c31d031d0239564ffffff239588feffffff8574fdffff19953cffffff52e86e320000 }

condition:
	$a0
}

        
