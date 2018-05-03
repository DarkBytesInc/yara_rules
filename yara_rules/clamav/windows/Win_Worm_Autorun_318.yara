rule Win_Worm_Autorun_318
{
strings:
	$a0 = { 5589e583ec2e2b0d8895400029c2eb4b39ffeb2c52c704248e9340005989c88b0d0b9340002b108b }

condition:
	$a0
}

        
