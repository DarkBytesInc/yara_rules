rule Win_Trojan_BAT_96
{
strings:
	$a0 = { 666f722025256120696e20282e2e5c2a2e626174[0-42]2530202525612073645f696e66 }

condition:
	$a0
}

        
