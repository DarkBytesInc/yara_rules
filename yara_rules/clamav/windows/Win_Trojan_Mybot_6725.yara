rule Win_Trojan_Mybot_6725
{
strings:
	$a0 = { 8d6f9b4f15f54ec6037f7e07693e1dc3439775c64bf45e22068bfba51a9caf9408e2cec2a112166929e27c9249c35748ca271ed39f99cd9919959f3798829fee65e7e98de5f7296442d79f7cc770a44ada6ccbaec247f34744f5aa1222f50f80ea12040eaaab75e37e39f71eefada7d866bcd90e6ada7cde2fb886ef791eeddfc3b21e57c4ec54ee39d2dc1d6012f27f65f30cdfb95e }

condition:
	$a0
}

        