rule Win_Trojan_Blackhole_42
{
strings:
	$a0 = { e803000000eb01c2bb55000000e803000000eb01c2e88e000000e803000000eb01c2e881000000e803000000eb01c2e8 }

condition:
	$a0
}

        
