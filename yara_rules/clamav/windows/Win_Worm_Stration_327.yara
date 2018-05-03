rule Win_Worm_Stration_327
{
strings:
	$a0 = { 195188d7e66b8134a89c70434ce315f13e47515bb39a31e4c32bd522a0ff0e5ac4dcccd1658634e169517862b1555e93ed7b121db360338c4fe28bd1cfb7b7965d732f0983356de2bee27ba7c7b3d7b7 }

condition:
	$a0
}

        
