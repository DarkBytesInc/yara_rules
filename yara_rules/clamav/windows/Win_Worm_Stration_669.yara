rule Win_Worm_Stration_669
{
strings:
	$a0 = { 364e00d9fbf6f6d4ffe2eed2f5f5f1dfffedffc2e29a89415047474c764d614e4b065622002c0e1f3c02ab0aa4ff050f041c390e081f6bdefcffffffcec0d7cbc0c996978bc1c9c9a500ffced9ddc8d9f9cad9d2c8fdbc006d52ff171a2e7267547663778bbdb5 }

condition:
	$a0
}

        
