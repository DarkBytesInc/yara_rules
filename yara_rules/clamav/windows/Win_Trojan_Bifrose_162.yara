rule Win_Trojan_Bifrose_162
{
strings:
	$a0 = { c00af02c0468283c1b0500efbd4f2238098105f5da7c7a5000c3359bdcb9033c6571804bb88248de543e008113c39b0f49f9e901f74a255702b75ecdded458527bba0b35 }

condition:
	$a0
}

        
