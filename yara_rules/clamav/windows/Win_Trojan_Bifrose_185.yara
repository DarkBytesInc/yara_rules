rule Win_Trojan_Bifrose_185
{
strings:
	$a0 = { f4568327c387b900d9c0fd033cda17e900e5ec884bde27133300d6e17f607892bd6600e7e8ad4ef9ef2dae002e8a730de9c137bc003ee0b5661768811900ef8863b40915 }

condition:
	$a0
}

        
