rule Win_Trojan_Lmir_199
{
strings:
	$a0 = { 6d626f426f784d49522e455845074441547f5b02da63502d4308494f4e2045526ff9ffee524f524f303132333435363738394142434643dbc27f7b496099a181b18199b991014301a3dbdbbffda383d17979bb00716373d3237173cf790b23a57376fbbffd792200299b3a0d4a83710b9b83f94b23e90e004213c2bb937d1a7b6b }

condition:
	$a0
}

        