rule Email_Trojan_Trojan_589
{
strings:
	$a0 = { 416e6a65316c6e61204a6f316965207030726e20766964656f2c2066696c652061747461636865642c2077617463682068696d }

condition:
	$a0
}

        