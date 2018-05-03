rule Win_Worm_Mydoom_86
{
strings:
	$a0 = { b844a360005064ff35000000006489250000000033c089082e2e2e24000258 }
	$a1 = { 6b1b696e67239f767a8a540fc5 }

condition:
	$a0 and $a1
}

        
