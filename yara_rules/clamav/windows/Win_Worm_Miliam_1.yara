rule Win_Worm_Miliam_1
{
strings:
	$a0 = { 85c0744c833d78b8400000754368fc814000ff75fc68248240008d8d80f9ffff8b460c8bd7e808f2ffff }

condition:
	$a0
}

        
