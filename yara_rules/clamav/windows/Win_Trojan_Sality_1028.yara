rule Win_Trojan_Sality_1028
{
strings:
	$a0 = { 60e85600000068??????008db500104000900334248bfe90682f10400055db04248bc7db442404dec1db1c248b1c2466ad51db04249090da8d7a104000db1c24d1e1290c24330424d1e966ab58e20b9057b8fc4f0000290424c3ffe333c981c1e8030000 }

condition:
	$a0
}

        