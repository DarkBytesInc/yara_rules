rule Win_Trojan_Killdisk_1
{
strings:
	$a0 = { 54524f2e434f4d0994014cc800000018d7bd911b2ae3688517148e345c2c05b8da13084a24a92835ab37a94815109844976e8529611483e094745c5463f95417a142b71a0ba568e6e2884c60238b7a4c2b6146be21f6df }

condition:
	$a0
}

        