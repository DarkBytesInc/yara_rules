rule Win_Trojan_Trojan_223
{
strings:
	$a0 = { bb0f00b980012e813762284343e2f7e9c4aea30cd2e3c570286436f1bbda6926e5431531781648d662d9d79de543bbf1ab894dd662af091066e106602807bbf1 }

condition:
	$a0
}

        
