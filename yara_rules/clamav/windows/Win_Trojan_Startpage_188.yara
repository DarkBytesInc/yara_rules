rule Win_Trojan_Startpage_188
{
strings:
	$a0 = { 6b4840008d45ecba02000000e800001e28c3e9000018f4ebeb5e5be800001ccc000057696e4d696e203a204d61696e00000057696e204d696e00ffffffff0c0000005c6f6c6568656c702e65 }

condition:
	$a0
}

        