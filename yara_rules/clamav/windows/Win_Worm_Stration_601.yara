rule Win_Worm_Stration_601
{
strings:
	$a0 = { 33c65ec39090909090909090558bec51e8000008??8945fc0f3133c23145fc8b45fc8be55dc39090909090 }
	$a1 = { 5c0000002e65786500000000 }

condition:
	$a0 and $a1
}

        
