rule Win_Trojan_W_409
{
strings:
	$a0 = { e8000000005db80000f7bf80384d75528bd8408138576a222b75f789850f0200008db5800100008dbdf301 }

condition:
	$a0
}

        
