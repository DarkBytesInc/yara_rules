rule Win_Worm_Antinny_25
{
strings:
	$a0 = { 8d45f4e85ff0ffff8d45fce86ff8ffffb804000000e871f9fbff85c0751bb806000000e863f9fbff8b1485e0b044008d45f0e8000dfcffeb62 }

condition:
	$a0
}

        
