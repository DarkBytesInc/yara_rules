rule Win_Trojan_Lmir_88
{
strings:
	$a0 = { 64206f66206d6972320000ffffffff080000005446726d4d61696e000000005445646974000000558bec33c0556867ce400064ff30648920ff0570f740007574803dbb0a4100007405e87dfdffffa174f7400050e8ae6cffffa178f7400050 }

condition:
	$a0
}

        