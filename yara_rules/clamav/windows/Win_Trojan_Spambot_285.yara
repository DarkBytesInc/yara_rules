rule Win_Trojan_Spambot_285
{
strings:
	$a0 = { 53d7d34c6adb3f216f15fd2fe279103f082a1e8916ff7ff4ff41b8fe89b59c6e9472ee8ac2ad5229a6f6ecf690e1083dbbef44ffffffff9e74e1a2870778b2c4c8e505f4290d9d4f827aee62ca18c1f80add521e5ba7eaf5ffffff5420728e93f8a1a25f03e8961283d8b469d7c9 }

condition:
	$a0
}

        
