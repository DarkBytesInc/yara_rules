rule Win_Worm_Mydoom_88
{
strings:
	$a0 = { b8942b89005064ff35000000006489250000000033c089 }
	$a1 = { 6c3332004578697450f86f7d }
	$a2 = { 6b696e677323 }

condition:
	$a0 and $a1 and $a2
}

        
