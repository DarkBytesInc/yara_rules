rule Win_Trojan_SdBot_2355
{
strings:
	$a0 = { 636fbeb4894a83c1d3f9ff37b587c3a2638ba45c415adbdbb766a3fd6f812353550bc5e39fe20213c2dcf02db0ac9e2c39073647e0bed5b47639d2c1ec9c8ccc5180d9edf0dcc334f1756ac0ae65b5d8ed3a9b1f1b }

condition:
	$a0
}

        
