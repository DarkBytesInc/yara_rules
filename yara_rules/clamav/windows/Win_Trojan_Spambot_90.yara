rule Win_Trojan_Spambot_90
{
strings:
	$a0 = { eb43becfedf75809a2d00c7098e6c9d83f2f062e69d20a441587849bffffffffd1365e0ab515c6ef212c6453d7d34c6adb3f216f15fd2fe279103f082a1e8916ff7ff4ff41b8fe89b59c6e9472ee8ac2ad5229a6f6ecf690e1083dbbef44ffffffff9e74e1a2870778b2c4c8e505 }

condition:
	$a0
}

        
