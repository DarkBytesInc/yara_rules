rule Win_Trojan_Agent_34922
{
strings:
	$a0 = { 42c0f0b547dc58692d6c8ca83e84b1e834c9a4e67fa3d01b86d958a936efe2550cfaaae123badf71ed027c9139d9e7a927c4df8538a0edb20682f01fe16886bd0ce5f6a800fd83e323e8a6a2576ce3b92bf2838538d6eda13597 }

condition:
	$a0
}

        
