rule Win_Trojan_Hupigon_835
{
strings:
	$a0 = { ebc92e06d0b4c8fcde201cdefc1da6a3ec5762b4489b7c4ddafe6cd1b0dbd3fb18a407dc81e50a998b9c67b49d6c3ff2a84225f7ed0507234e563fa8f41ac2c05cb7cb3ab266dfdd12333abbebb2e65fbbea0e6728669de2679e18fce564ae }

condition:
	$a0
}

        
