rule Win_Trojan_Mybot_8469
{
strings:
	$a0 = { f1dff6d198fab0a807cc403b434134f71556feec183ac97a126d194e3ba69f66cdf785d6daa88af726f8ec5b4aa04e4af00e684ad1b8bcf12dec1b9e23ac6f38f512604a9bdd5729a0da1a64fd3eba623b3d623d0e }

condition:
	$a0
}

        
