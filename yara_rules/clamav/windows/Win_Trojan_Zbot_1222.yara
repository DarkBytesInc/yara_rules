rule Win_Trojan_Zbot_1222
{
strings:
	$a0 = { e9240000009300001c59002d46000078de00b90000d000b100c0ba280094c78beb0045244c098f4300 }

condition:
	$a0
}

        
