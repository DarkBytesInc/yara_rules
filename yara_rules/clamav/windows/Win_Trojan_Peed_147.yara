rule Win_Trojan_Peed_147
{
strings:
	$a0 = { e8f100000089e00110c3ba0400000087d1586866f40f00ff1580??40006800000002680e7005 }

condition:
	$a0
}

        
