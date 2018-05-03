rule Win_Worm_Stration_537
{
strings:
	$a0 = { 90558bec51e8????????8945fc0f3133c23145fc8b45fc8be55dc390 }
	$a1 = { 81c4????0000c39090 }

condition:
	$a0 and $a1
}

        
