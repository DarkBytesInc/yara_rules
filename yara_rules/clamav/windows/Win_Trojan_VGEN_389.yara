rule Win_Trojan_VGEN_389
{
strings:
	$a0 = { 909090e800005d8bdd81c3180043fa8a1788168e03891e8f03eb00c6070beb0190e800005881ed0701eb0c90e80000 }

condition:
	$a0
}

        
