rule Win_Trojan_Bancos_1772
{
strings:
	$a0 = { bb1e5ae4d633d52c7732ff51139aeec3781ef171e52d110632110940752ac93bfa986aa9de5e18551ac8e8d224309394110a70186b0cc0590e029aae8a1bdea453a62be501a3 }

condition:
	$a0
}

        
