rule Win_Trojan_Dialer_672
{
strings:
	$a0 = { 322e6436000065c18922fb594907fcff4f484b45595f43555252454e545f55534552a7596db52b3a7761f55c48ab525d3d5c496ee56ed327a9adb57a78706c280b1b61d8606a6b5f2b74281550da1f59031acf385f383939ff60cbfe3130333036??2000172d3031325f352dfb7694fc????????????77002e62616361adb66a756d696960695316a0d56f0e697a2f6c61 }

condition:
	$a0
}

        