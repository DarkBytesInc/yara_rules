rule Xls_Trojan_Remeel_1
{
strings:
	$a0 = { 496620576f726b626f6f6b732861292e564250726f6a6563742e5642436f6d706f6e656e74732e4974656d2831292e436f64654d6f64756c652e4c696e657328332c203129203c3e20222752656d65656c22205468656e204525203d203720456c7365204525203d2038 }

condition:
	$a0
}

        