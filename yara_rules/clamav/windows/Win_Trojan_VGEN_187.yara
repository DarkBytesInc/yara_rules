rule Win_Trojan_VGEN_187
{
strings:
	$a0 = { 01b409cd21cd20e93b075468697320697320612074696e7920434f4d2070726f6772616d2c207061646465642074 }

condition:
	$a0
}

        