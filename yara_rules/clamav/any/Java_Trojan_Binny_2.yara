rule Java_Trojan_Binny_2
{
strings:
	$a0 = { 150c840c010153190d150c840c01bb00175904b7001853190d150c840c01bb00175904b700185319062d190db60019572b121ab600054d2cb6001b57a700084c2bb6001db10001000401130116001c000100230000 }

condition:
	$a0
}

        