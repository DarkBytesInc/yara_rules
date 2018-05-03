rule Html_Trojan_Fraudpack3858_1
{
strings:
	$a0 = { 558bec6a002eff1554a0420083f8ff743a502eff1550a0420083f800752d6a006a006a006a00502e }

condition:
	$a0
}

        
