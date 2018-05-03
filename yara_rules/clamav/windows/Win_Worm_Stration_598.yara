rule Win_Worm_Stration_598
{
strings:
	$a0 = { 5c0000002e6578650000000042b0c57235ac7fb62db4e8809b75bab4000000004b }

condition:
	$a0
}

        
