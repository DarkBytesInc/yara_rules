rule Win_Trojan_Bancos_1074
{
strings:
	$a0 = { 147ee67b4d50a690040e2635bc15d81093a1703b8614966348ad305d71b666210e65b6eb8a140e29aad4afb708107ef31472b064ccd17c9cf12964cbdba69e41bdbcd337aca90e839e0bdc3dc4c8888bf85c3f2f4a }

condition:
	$a0
}

        
