rule Win_Trojan_NGVCK_11
{
strings:
	$a0 = { e8000000004483c4038b5424fc81ea05204000525d2bd203d585d27419bb5d0300008bfd81c7362040008b0ff7d9890f }

condition:
	$a0
}

        
