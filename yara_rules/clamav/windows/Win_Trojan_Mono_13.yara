rule Win_Trojan_Mono_13
{
strings:
	$a0 = { 8b??8b??909090[0-50]8b??909090[0-50]8b??909090 }

condition:
	$a0
}

        
