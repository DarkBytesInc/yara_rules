rule Win_Worm_Stration_594
{
strings:
	$a0 = { 5c0000002e657865000000000cc196bc97344c93ba78f441b052a981000000000a }

condition:
	$a0
}

        
