rule Win_Trojan_Small_3927
{
strings:
	$a0 = { edb2c02ac2053d3dfeb1b36e95425466ad3502720006a86504b2b35eadc82d77edb2c6aba1408362013e7316bff23db63af831b615c63d66cdb1b35e75f8396aadb23d6584ec9a5a22d5bee3a17b3e66ad2657e72aa7d267adb24ceadbb53d6674f82d67adb23d4fd0b5 }

condition:
	$a0
}

        
