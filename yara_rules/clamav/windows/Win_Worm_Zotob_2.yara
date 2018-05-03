rule Win_Worm_Zotob_2
{
strings:
	$a0 = { 8a7e6e4ec2d19e927172ac56db5fdc958b0ce824b105d1b2854ef09dda3d253f516765fcf95980480dd7fcdde3dbe78e94c7fae8e7445d0b3cecd8a25c99bb391db90fea506e528cd3142703a2ed3d4bce602f628cae6efafb9343fa4e208a23 }

condition:
	$a0
}

        
