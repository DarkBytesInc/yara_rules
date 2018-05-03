rule Win_Worm_OpaSoft_6
{
strings:
	$a0 = { 52551247d7d973e961b2645445595f72ffff7f899f6b9e4ccc56e7eea36033734c3f7312325baeac }

condition:
	$a0
}

        
