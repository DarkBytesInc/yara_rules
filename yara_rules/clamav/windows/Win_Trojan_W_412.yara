rule Win_Trojan_W_412
{
strings:
	$a0 = { e8000000005d8bcd83e90581e900100000898dba000000b80000f7bf80384d75528bd8408138576a222b75 }

condition:
	$a0
}

        
