rule Win_Trojan_Lineage_348
{
strings:
	$a0 = { 4e4c9c2d0dd990fe25d74026247179ea33f82c938446fc0caa9306bc6959b88bfe3003e8e679e484305db79a92bc2573ac8e3fd839d4c53677074a056d46bdf1b84d295947186dc5498105b09c1d1ee610272d2660032022b9081cebf21e0d5c52252fd6be112d71eb181d37 }

condition:
	$a0
}

        