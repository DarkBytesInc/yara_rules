rule Win_Trojan_Bancos_853
{
strings:
	$a0 = { 68747470733a2f2f7777772e6d62616e6b2e636f6d2e706c2f69625f66725f686f6d6562616e6b696e672e617370 }

condition:
	$a0
}

        
