rule Win_Worm_Stration_682
{
strings:
	$a0 = { 5589e56aff6818??400068????400064ff35000000006489250000000083ec505356578965e80100????02e80100????59a3dc??4000e80100????85c075086a }
	$a1 = { 005c002e65786500ffffffff }

condition:
	$a0 and $a1
}

        
