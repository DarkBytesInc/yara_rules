rule Win_Trojan_Phardera_2
{
strings:
	$a0 = { bf935580c3ebb45fb17c80ee6d1b7de2bfcffdb93f41bb81efbe56b383d96087c94281d9670b330a12a666f186cd81d2961c80fea6bd37f380ca11b92e7f48bf1ece86e283ff51231081c2151981c1371db412bf8dccbf28c03a52df4087fd83e29c81e27f204280e4abb89b8e }

condition:
	$a0
}

        
