rule Win_Worm_Stration_280
{
strings:
	$a0 = { eb098da424000000008bff8a5c0c308a540430885c04304088540c30493bc17cea33c0eb06 }

condition:
	$a0
}

        
