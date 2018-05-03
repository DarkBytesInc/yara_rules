rule Win_Worm_Agent_36214
{
strings:
	$a0 = { 55505821 }
	$a1 = { 5249564d5347206b203a5b }
	$a2 = { 6f67696e5d206879647261202d20796f75 }

condition:
	$a0 and $a1 and $a2
}

        
