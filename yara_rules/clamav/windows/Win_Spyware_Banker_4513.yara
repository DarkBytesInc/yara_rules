rule Win_Spyware_Banker_4513
{
strings:
	$a0 = { 1b24529bcae6222e72cda7b5eff5eb224a90842c64d9873e00cd8999e4124bfe5e4b4d6240666541730498abb9c6478d2c94d0??????????????????????38ab01ebdcd181d3068005c62358111c9d111dcf63cd1d14de5838c01a3004503f03 }

condition:
	$a0
}

        
