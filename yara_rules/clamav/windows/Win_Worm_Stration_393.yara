rule Win_Worm_Stration_393
{
strings:
	$a0 = { 8edd52564bdcbe837a09ccd18e91a28cb7ea13ca3993eb880aa62ad25e2ba8e2e7efd6771718f330a13dcf8c88a2c839c7acc4c555cab4ef9dedf803d5fd3f20ae5e758a70e21bcc5b1f086010fed03345e52c668165e4efe40db477ce36dc94ad168569cf3f068d6abc2d221ed7bf80 }

condition:
	$a0
}

        
