rule Win_Trojan_Mybot_6263
{
strings:
	$a0 = { ff5594ab32ac0067136a01af4c56f5eab80e3afe3f0223fa5595b8a3df7f00be19a1863c8c90f70eeac7d559ae083f837175f41088ae6f8c03fe07e359ea8ea8573aeeebfba817b8fb3a97e8832040abe3eaa8491aa2000d08f1 }

condition:
	$a0
}

        
