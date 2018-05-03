rule Win_Worm_Plea_1
{
strings:
	$a0 = { 2e4243433d612e41646472657373456e7472696573283229202620223b2022 }

condition:
	$a0
}

        
