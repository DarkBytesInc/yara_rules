rule Win_Trojan_Pincav_12
{
strings:
	$a0 = { 558bec6aff68c850400068????400064a100000000506489250000000083ec585356578965e8ff????50400033d28ad48915????40008bc881e1ff000000890d????4000c1e10803ca890d????4000c1e810a3????40006a01e8a50a00005985c075086a1ce8c300000059e8c509000085c075086a10e8b20000005933f68975 }

condition:
	$a0
}

        