rule Win_Trojan_Renos_29
{
strings:
	$a0 = { ffff771229d281c2c6000000239580feffff85d273008b9568ffffff4229ca138d20ffffffff8528ffffff4a29ca399570ffffff7716b9260c000081c1001d000083f9007306ff85b8feffff09caff8d74feffff2995e8feffff29d2318d60fdffff31d1 }

condition:
	$a0
}

        
