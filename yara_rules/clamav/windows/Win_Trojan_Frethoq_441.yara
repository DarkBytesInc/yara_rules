rule Win_Trojan_Frethoq_441
{
strings:
	$a0 = { f9fcfcfdf7fff9fefdf8f9fcfcfdf7fff9fefdf8f9fcfcfdf7fff1fefdf8071bb60bf7b302cb1eb0fa48c91e4b6762711d686b6b636f586c19615e66676b701d59641970726619656a1d3b4e4c1e6a675d612a }

condition:
	$a0
}

        
