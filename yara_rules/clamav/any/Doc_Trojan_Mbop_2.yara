rule Doc_Trojan_Mbop_2
{
strings:
	$a0 = { 6d626f7056636d626f70203d204d6964286d626f7056636d626f702c20312c20496e537472286d626f7056636d626f702c20226d626f702229202d2031292026206d626f70546e6d626f702026204d6964286d626f7056636d626f702c20496e537472286d626f7056636d626f702c20226d626f702229202b204c656e28226d626f70222929 }

condition:
	$a0
}

        