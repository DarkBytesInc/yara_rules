rule Win_Worm_Sorin_1
{
strings:
	$a0 = { 49462025534f5249253d3d33 }
	$a1 = { 434f50592052756e646c6c2e626174205c5c2541444452455353255c41444d494e245c53595354454d33325c25574f524d25 }

condition:
	$a0 and $a1
}

        