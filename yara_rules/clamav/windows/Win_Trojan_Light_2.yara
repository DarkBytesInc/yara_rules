rule Win_Trojan_Light_2
{
strings:
	$a0 = { 5900c8000100bf56001e578dbe00ff16576a009a670b59009a35095900bf56001e576a019a70095900ff360200 }

condition:
	$a0
}

        
