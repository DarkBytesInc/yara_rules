rule Win_Worm_Stration_531
{
strings:
	$a0 = { 5c0000002e6578650000000089aea6afb2ada1b4a9afaec000000000496c787d }

condition:
	$a0
}

        
