rule Win_Trojan_Spambot_202
{
strings:
	$a0 = { ab3540edc4b3cb9397ffc2c0ff6d734d0e0b1a24a56f0b3b02bfd41a1aecffffffffbf3de22b0c13961aa352d98c022f41ecc84b219e7c4e90cb3946f815fd60f62effff57ffaa38235847656bc1530d0d2b2aaa0378050e0f28be54e712dcdbffffffff0297f63aaaa24e86431b }

condition:
	$a0
}

        
