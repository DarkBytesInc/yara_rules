rule Win_Worm_Stration_353
{
strings:
	$a0 = { 70517bb4a897a72dfe9975104713656a3ac6a79391266932a34efaf36bce0b27fee58089f47c51670cccaa08d979580ca1b2e2dcced37dca453c2b289bfa2a658be5e2ba795aa4462b8edd67b1839a4e }

condition:
	$a0
}

        
