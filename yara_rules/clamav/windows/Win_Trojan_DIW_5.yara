rule Win_Trojan_DIW_5
{
strings:
	$a0 = { e926092a2e636f6d00e9190080002a2e657865005abf00018bf283c609b90300f3a4528bc2052a0050c32e9c58 }

condition:
	$a0
}

        
