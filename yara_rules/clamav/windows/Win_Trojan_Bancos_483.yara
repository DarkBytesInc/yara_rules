rule Win_Trojan_Bancos_483
{
strings:
	$a0 = { 61697861206465206469e16c6f676f0000ffffffff290000005c436174526f6f745c7b393939393939393939393939392d313233343536372d303132333435367d5c000000ffffffff10000000617377303073756564616d612e68676600000000ffffffff1b0000004d6963726f73 }

condition:
	$a0
}

        