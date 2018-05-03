rule Win_Worm_Rosk_3
{
strings:
	$a0 = { c745fc10010000c785f0faffff6caa4000c785e8faffff08000000b810000000e84ab2feff }

condition:
	$a0
}

        
