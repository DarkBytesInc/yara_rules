rule Win_Worm_Stration_597
{
strings:
	$a0 = { 5c0000002e6578650000000073e9c84d5d9798f7371b }

condition:
	$a0
}

        
