rule Win_Trojan_Zbot_1294
{
strings:
	$a0 = { e9c9050000558bec83ec58816db457510000684c373550518d55e45250683143376f51ff75fc8d55f452e8 }

condition:
	$a0
}

        
