rule Win_Trojan_SdBot_2797
{
strings:
	$a0 = { b3c60f4a03d064bd117895ffe1553e412ac85c812546e3b039309a1517ea32db75dc5e881b3b8d75d7a49b6895fe42b48f8e878a7c3c1792204420535099ea84cc3b7994a4493fc84fde4ce304ee1ace381efcd1a3f9be9f580d8c13930e8dce4cc2fcde64d44ae9fd2f63f4da73bba8d306f191118091c82b1fdf464480891f544cf8307ead19850113ddd7d0640830ff37e8bfe493 }

condition:
	$a0
}

        