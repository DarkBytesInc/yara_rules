rule Win_Trojan_W_411
{
strings:
	$a0 = { e8000000005d8bcd83e90581e900100000894d71b80000f7bf80384d75528bd8408138576a222b75f789 }

condition:
	$a0
}

        
