rule Win_Trojan_Ransom_42
{
strings:
	$a0 = { 558bec6aff6848614000689836400064a100000000506489250000000083c4c05356578965e8c745fc00000000c745d000000000eb098b45d083c0018945d0817dd0102700007d1eff150c504000a39c344100833d9c3441000075086a00ff1500504000ebd06a006a006800000400ff1510504000a39c34410068631000006a }

condition:
	$a0
}

        