rule Win_Trojan_W_410
{
strings:
	$a0 = { e8000000005db80000f7bf80384d75588bd8408138576a222b75f7ff75648985c20200008db52e02 }

condition:
	$a0
}

        
