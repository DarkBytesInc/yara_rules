rule Win_Spyware_Banker_3071
{
strings:
	$a0 = { 32ebb66f62326f7f3938513eca4534eea7c46a35c6a1a6001934e19dd5476e94c4c3f5e768572305a68d96caa2ba4b032eb224b1214f14ef49676151573e315d1ddeedf7bf6d1f }

condition:
	$a0
}

        
