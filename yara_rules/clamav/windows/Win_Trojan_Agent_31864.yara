rule Win_Trojan_Agent_31864
{
strings:
	$a0 = { b85b73374f772ef778aa187025736d5c06886caea97921434870363a64342f310d0a112022b95ee3146966ce92b4e7220ff667796fe5eab2250d2ecb0a2ea47325258b30812e2fba158a626174947a272e2fdbca0e088407a355da16248f542301df57c14d5a90c10399110409ffc605b83418eb2b0cccc8090e391fbaf001b409cd21b8014c800a5468697320701c726f67cf616d }

condition:
	$a0
}

        