rule Win_Trojan_Okanpi_1
{
strings:
	$a0 = { 5f4f736361725f5374617475734e6f746966790023333237373000005f41696d41640000576e644174653332436c6173730000005f4f736361725f49636f6e42746e00005f4f736361725f547265650041494d5f494d65737361676500000000[0-5]436c617373[0-6]436c617373 }

condition:
	$a0
}

        