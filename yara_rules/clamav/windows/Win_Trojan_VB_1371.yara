rule Win_Trojan_VB_1371
{
strings:
	$a0 = { 4000ff2560104000ff2580104000ff255c104000ff2504104000ff256c104000ff2574104000ff2538104000ff254c104000ff2518104000ff2528104000ff2514104000ff2540104000ff2558104000ff253c104000ff2520104000ff2534104000ff2500104000ff257c104000000068a8114000e8eeffffff000000000000300000004000000000000000a597dbfa47910e429fd9235303b430ad000000000000010000006f722042696e50726f6a6563743100696c654f0d0a200000000056423521f01f2a000000000000000000000000007e000000000000000000000000000a000904000000000000e01240000413400000f0300000ffffff080000000100000000000000e9000000a8114000a811400064114000780000007c0000008500000086000000000000000000000000000000000000005374620050726f6a65637431000050726f6a65637431000001000000c026400000000000ffffffffffffffff000000001427400000a0410004000000d01240001800200000000000b4161e0070124000ec124000f8124000 }

condition:
	$a0
}

        