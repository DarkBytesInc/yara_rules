rule Win_Trojan_Packed_50
{
strings:
	$a0 = { e925e4ffff000000 }
	$a1 = { 70ffff70000000008fffff3709fffff3b0ffff70000000008ffff33b09900000030fff70000000008ffff3b709011770000fff70000000008ffff33b099991f7000fff70000000008fffff37 }

condition:
	$a0 and $a1
}

        
