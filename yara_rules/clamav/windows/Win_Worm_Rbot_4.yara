rule Win_Worm_Rbot_4
{
strings:
	$a0 = { 4dedbdc66e3e070deae95f0091ea65de6044ef6e3e4280d97bf546d39f9de65eb1fc4959fc3469ac86be641dc14b6cc49cd011a1b956ee40276683664d26a019 }

condition:
	$a0
}

        
