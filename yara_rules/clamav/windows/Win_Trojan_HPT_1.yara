rule Win_Trojan_HPT_1
{
strings:
	$a0 = { 68a900007ea9000090a90000a2a90000bca90000cea90000e0a90000f0a9000000000000730000807400008000000000000000002f68702f737461727475702e74787400257325642e25642e25642e2564257300687474703a2f2f002f68702f68702e65786500007b37344137394237372d464236462d344537322d383145452d4332323146393234314343327d0000534f }

condition:
	$a0
}

        