rule Win_Trojan_Sality_1059
{
strings:
	$a0 = { eb0589cff6c5d48bd7eb0c0fbedd0fbec069df462f916523db86d288e0eb078bf584c40fb6ed81f952ae00002bc8686f2c840057ffc18bdb86ff85f8b07cffcac6c230e81100000086ff89d7b2bd0fbef081f1918b00003c1881d79efe07cff6c3930faff085c17208bd71512c200faff6eb080fb6ea03d20fafd681f9ecaa00 }

condition:
	$a0
}

        
