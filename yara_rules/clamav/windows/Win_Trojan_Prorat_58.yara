rule Win_Trojan_Prorat_58
{
strings:
	$a0 = { e0ebc57c09793792f25e4df3ff3cdf7df07feffad75e6bc618ddf73ee103852a239ff4b7500e7fc975bbd87dff5a1efca76cebfd267fd71f8dd9f3ee4b1f7f9dfa77c07f6290a556f979f3df5b580f72df4cc9bcbf245a9f732e44365f7d8121e48baca69019a3de91e2c459a7a93f5b1625e343e91a22a2f61a22d87543f97e16d7bc2c8d2d72dafafcffdf }

condition:
	$a0
}

        