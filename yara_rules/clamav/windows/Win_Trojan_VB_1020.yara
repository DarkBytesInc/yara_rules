rule Win_Trojan_VB_1020
{
strings:
	$a0 = { 68c8774000e8f0ffffff00000000000030 }
	$a1 = { 32005c007500700064006d006e00670072002e006500780065 }

condition:
	$a0 and $a1
}

        
