rule Win_Trojan_Katusha_3
{
strings:
	$a0 = { 3395a4feffff81ea000f00002b9508feffff2b95b8feffff199508feffff19959cfeffff21954cffffff31c201c283fa00772b8b45882185a0feffff8985a4feffff81c00001000081c0a8000000338518feffff85d2730681c2b90000008b4da8218d14 }

condition:
	$a0
}

        
