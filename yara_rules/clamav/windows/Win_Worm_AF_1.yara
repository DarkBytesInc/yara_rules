rule Win_Worm_AF_1
{
strings:
	$a0 = { b815a69d5785198f92991e992a497cfe0dccec7871a74386be1250403c81c3fe65427a8972cc620decf87c9b3875790cbd2a99f283433e87586a047cbde25b82 }

condition:
	$a0
}

        
