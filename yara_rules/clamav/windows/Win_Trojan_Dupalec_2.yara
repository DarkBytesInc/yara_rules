rule Win_Trojan_Dupalec_2
{
strings:
	$a0 = { 06015589e5b800029a7c02060181ec0002c706c400c807c706c6000800c706c8001e00c706ca000900c706cc00 }

condition:
	$a0
}

        
