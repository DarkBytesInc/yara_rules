rule Win_Trojan_Spambot_260
{
strings:
	$a0 = { c8d243a633758943bd66f3961856a32f5d83e362b3d01f4dbc01a6ffff8bffa88fc09b62055e61553de66b706a8ace0655c84cf3b2dc6096f8ffffe9ff977b29eebf960d45eaf86e7588396e7a15345b425f01c2081f3afffffff7aac4bfaaa5cf35e05ad59a10ed1e750db6ed3f }

condition:
	$a0
}

        
