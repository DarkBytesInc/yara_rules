rule Win_Trojan_Bancos_1927
{
strings:
	$a0 = { 4f4e12fe9e105a5571c95bb4eb38760a76655c2aa0ffa386b4e39b7f4d4be8e3abda8746c59db8b43a3970c37ef78bef87d0e597bddfff4f63747cf0aa13a02353d3ad5cb2b36eb72ead91208c1f711adedf8322f28a7b21f7f7 }

condition:
	$a0
}

        
