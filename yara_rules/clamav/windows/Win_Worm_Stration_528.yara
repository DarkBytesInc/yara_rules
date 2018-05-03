rule Win_Worm_Stration_528
{
strings:
	$a0 = { 5c0000002e6578650000000098bfb7bea3bcb0a5b8bebfd1000000004e6b7f7a6f7e3b686e78787e }

condition:
	$a0
}

        
