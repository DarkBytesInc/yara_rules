rule Win_Trojan_VB_1352
{
strings:
	$a0 = { 98104000ff253c104000ff2518104000ff258c104000ff2584104000ff250c104000ff2554104000ff2524104000ff2550104000ff2570104000ff257c104000ff2580104000ff2548104000ff2544104000ff2534104000ff2540104000ff2510104000ff2564104000ff258810400068fc114000e8f0ffffff00000000000030000000380000000000000076136ad47a5cf04bbc84f5e24a10434d0000000000000100000000000000000000000000000000000000000006000000203540005642352136262a000000000000000000000000007e000000000000000000000000000a00090400000000000048144000bc19400000f1b00000ffffff080000000100000003000000e900000088124000f4114000b8114000780000007e000000840000008500000000000000000000000000000000000000000000000000000000000000000000000000000050000000738e1649a971e943b2364105f620df4d00000000000000000000000000000000010000000001000000000000000000000000000000000000000000005f010000 }

condition:
	$a0
}

        