rule Win_Spyware_Banker_3379
{
strings:
	$a0 = { 34b3406f8ce9f3dc7edc71bc4d899702c3b4d430f00dd7d4168184e27b39f08a7913751986e5fdb25f17d4623456de1373576b93dde2627b052a542fd4c3d33e69ecc8c379ff }

condition:
	$a0
}

        
