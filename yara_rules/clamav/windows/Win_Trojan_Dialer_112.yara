rule Win_Trojan_Dialer_112
{
strings:
	$a0 = { 656b7400005c646174696e673736322e65786500005c444154494e472e4c4e4b00434f4e4e4543543736320000434f4e4e4543540030303234363335333534363200000000687474703a2f2f7777772e7365786669 }

condition:
	$a0
}

        