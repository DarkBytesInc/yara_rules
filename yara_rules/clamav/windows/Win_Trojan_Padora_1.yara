rule Win_Trojan_Padora_1
{
strings:
	$a0 = { 6a0068800000006a026a006a0068000000408b45fc50e8b3f9ffff8bd883fbff7506c645fb00eb186a008d45f450575653e8f8f9ffff53e882f9ffffc645fb0133c05a5959648910eb0ae92ff1ffffe88ef2ffff8a45fb5f5e5b8be55dc3 }

condition:
	$a0
}

        
