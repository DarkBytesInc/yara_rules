rule Win_Trojan_IniKill_2
{
strings:
	$a0 = { 104000ff2590104000ff25f810400068d01a4000e8f0ffffff000000000000300000004000000000000000b45bf6484ae1d211a26654d703c100000000000000000100000000001c4275016578706c6f72657200c1400008c1400000000000ffcc310004635bf6484ae1d211a2 }

condition:
	$a0
}

        