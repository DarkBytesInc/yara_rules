rule Win_Trojan_Sality_1013
{
strings:
	$a0 = { 88c700108b0d44620010518b55fc52ff1598100010a3fcc00010a14c620010508b4dfc51ff1598100010a378c700108b1550620010528b45fc50ff1598100010a3f86a00108b0d54620010518b55fc52ff1598100010a354c30010a158620010 }

condition:
	$a0
}

        