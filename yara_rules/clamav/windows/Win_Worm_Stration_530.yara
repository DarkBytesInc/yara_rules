rule Win_Worm_Stration_530
{
strings:
	$a0 = { 5c0000002e65786500000000476068617c636f7a6761600e }

condition:
	$a0
}

        
