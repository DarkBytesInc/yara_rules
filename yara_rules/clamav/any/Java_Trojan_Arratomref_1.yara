rule Java_Trojan_Arratomref_1
{
strings:
	$a0 = { cafe(babe|d00d) }
	$a1 = { 4341464542 }
	$a2 = { 303030303033303030 }
	$a3 = { 30303245303030303030303230303246 }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
