rule Win_Trojan_Lolu_1
{
strings:
	$a0 = { 6e23692300000000ffffffff0400000022202f6600000000ffffffff0100000041000000ffffffff0100000043000000ffffffff07000000636d }
	$a1 = { 6f72644c756369 }

condition:
	$a0 and $a1
}

        
