rule Win_Trojan_Mybot_8394
{
strings:
	$a0 = { b2c447549470d31a9641cca2a015cbd79ca871794dd54e099c3fecdf4d6c72142d547aab0d8c38e4dd2e08d82241596df61600f93ff32fc4f5c3cbced74fd7855c116320d68db788d1997464ab62a846a31ac4cc7c }

condition:
	$a0
}

        
