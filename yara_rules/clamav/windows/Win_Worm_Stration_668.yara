rule Win_Worm_Stration_668
{
strings:
	$a0 = { 4574636772635269696a3f6a76353455686776756e69728117f8174df7d5c8c4c2d4d497e1ced5a0ffffbf4090f9dbc6caccdada9a9be7ccd1dda9006b574d5a5e5bffffffff0c0d79 }

condition:
	$a0
}

        
