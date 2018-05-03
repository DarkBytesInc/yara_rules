rule Win_Worm_Stration_581
{
strings:
	$a0 = { 6ffc2b262f262d43953c3b2a2a275ec2c8dbccc7a9ef5e32bff1fdf2ffe5319486e73fd6c4cbc1f237fed6d7c4d51d181f151071e5476167757a149bd8d8fc3d }

condition:
	$a0
}

        
