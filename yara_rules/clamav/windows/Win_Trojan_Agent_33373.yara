rule Win_Trojan_Agent_33373
{
strings:
	$a0 = { a0e9cd22e32683a56fd770cc23abe75e224674d3835fea99cdd4c3166d6beaee9692ebe9c209bcab17e97b5e7cba0337944dab3801292bcd56d87341e1783f8c2cfaeb66f57c40d9ae6795812057b97f19fba103986a3723fb97a443 }

condition:
	$a0
}

        