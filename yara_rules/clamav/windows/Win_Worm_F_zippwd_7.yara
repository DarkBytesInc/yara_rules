rule Win_Worm_F_zippwd_7
{
strings:
	$a0 = { 706173733a }
	$a1 = { 6170706c69636174696f6e2f7a69703b }
	$a2 = { 6e616d653d }
	$a3 = { 2e7a6970220d0a }
	$a4 = { 0a5545734442416f414151414141 }
	$a5 = { 414141414141414141 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5
}

        
