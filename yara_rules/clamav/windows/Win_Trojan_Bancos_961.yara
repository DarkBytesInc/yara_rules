rule Win_Trojan_Bancos_961
{
strings:
	$a0 = { 1f26d704205aa4ca7e99296b8457af3f52560e600dd0e4d4e9341a2e3226b92d91fca916dc05bda3adfa207da0cdc39b00a19d6cdc1830151c2502e5ecc1c400b6a466429e77ab0cc0ac24cac326ac9e39528756c8c9c0c3 }

condition:
	$a0
}

        
