rule Win_Trojan_Gen_191
{
strings:
	$a0 = { bf1c06b8000050579a7101e70031c0509a8401e7005dcb185465726d696e61746520626163 }

condition:
	$a0
}

        
