rule Win_Trojan_Renos_32
{
strings:
	$a0 = { 40fdffff29d20195dcfeffff139574fdffff218d7cffffff218d1cfeffff018df8fdffff214da429d241898d1cfdffff098d3cfdffff29c909d1318db0feffff898dfcfdffff194d8481c2000300002b8d20fdffff2b8d60fdffff31d20195b0fdffffff }

condition:
	$a0
}

        
