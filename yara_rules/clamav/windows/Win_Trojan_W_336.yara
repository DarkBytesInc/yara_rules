rule Win_Trojan_W_336
{
strings:
	$a0 = { f7e18038010f846a02000068b2060000cd200d0040005985c00f84560200009757e8 }

condition:
	$a0
}

        
