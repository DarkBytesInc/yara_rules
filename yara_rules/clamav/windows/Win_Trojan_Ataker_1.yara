rule Win_Trojan_Ataker_1
{
strings:
	$a0 = { 56c1e8108ad4be106840000fb6d20fb6c0525033c08ac50fb6c0500fb6c150687863400056ff15b451400083c4188bc65ec38b0d3468400085c974088b016a01ff10ebeec3e8e8ffffff6840684000ff15c0504000a13068400085c0740750ff1560514000c3558bec8b450c5648480f84ef0000002dce0b00007417ff7514ff7510ff750cff7508ff1568514000e9db0000008b3534 }

condition:
	$a0
}

        