rule Win_Worm_Stration_602
{
strings:
	$a0 = { c65ec39090909090909090558bec51e80000????8945fc0f3133c23145fc8b45fc8be55dc3909090 }
	$a1 = { 5c0000002e65786500000000 }

condition:
	$a0 and $a1
}

        
