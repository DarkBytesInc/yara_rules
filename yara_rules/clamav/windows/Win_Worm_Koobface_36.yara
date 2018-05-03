rule Win_Worm_Koobface_36
{
strings:
	$a0 = { 74776900747465722e[0-23]4661634500000000626f }
	$a1 = { 504f5354 }
	$a2 = { 23426c41636b6c }
	$a3 = { 78322e646174 }
	$a4 = { 3536373738382e626174 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}

        
