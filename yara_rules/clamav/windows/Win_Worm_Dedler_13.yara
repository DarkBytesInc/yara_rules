rule Win_Worm_Dedler_13
{
strings:
	$a0 = { 5657be201040008d7df4a5a56818104000a5e8aeffffff }

condition:
	$a0
}

        
