rule Win_Trojan_F_22
{
strings:
	$a0 = { e8b5025383ed0433c048cd210bc074501e8cc34b8edb803e00005a7540bb8000291e0300291e12008e06120033c08e }

condition:
	$a0
}

        
