rule Win_Trojan_FakeAV_113
{
strings:
	$a0 = { 1e0000ff85b0fdffff018598feffff85c074280b8d7cffffff334d9429c9098d3cfdffffff8d28fdffff2b4d9c198594feffffff45b001c883e83d118dd0fdffff318df8feffff118d40fdffff318d84fdffffff1570d04000b8ea0b00000b8554feffff }

condition:
	$a0
}

        
