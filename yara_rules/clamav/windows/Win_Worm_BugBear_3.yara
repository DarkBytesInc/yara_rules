rule Win_Worm_BugBear_3
{
strings:
	$a0 = { 3400555058210c09020a7621ab4c1f1e4337c7ed07001511010000900200260b0024 }

condition:
	$a0
}

        
