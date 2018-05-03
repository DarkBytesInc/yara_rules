rule Win_Worm_Autorun_381
{
strings:
	$a0 = { 5c436f6d6d616e643dd6d8d2aad7cac1cfb1b8b7dd2e657865 }
	$a1 = { 5c6e31323365772e646c6c }
	$a2 = { 5c2424666c617331687024242e626174 }

condition:
	$a0 and $a1 and $a2
}

        
