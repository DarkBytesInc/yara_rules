rule Win_Trojan_Edlack_1
{
strings:
	$a0 = { 5e5958eb0800000000000000008bc88b3e03bd220400008bb552010000c1f902f3a58bc883e103f3a45e68008000 }
	$a1 = { 426c61636b44656164 }

condition:
	$a0 and $a1
}

        
