rule Win_Trojan_Bancos_1292
{
strings:
	$a0 = { 8e6177163f0bf8cbe8f0823bfa8a763a7aa716fbe78703e1998105bdb8d040f567b69a71d76239ff48737cfc73bbf37b6c5b362a4af99296ce1320f13e14bcd8645ccf077dd4d6b0294b9f594a9d539e61e1 }

condition:
	$a0
}

        
